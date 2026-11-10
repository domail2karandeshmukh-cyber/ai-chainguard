// The hero's bench. Paper side: the browser downloads the model file that experiment E2 signed and
// deployed, byte for byte, and re-runs two of the verifier's ten checks with Web Crypto: the file's
// SHA-256 against the signed manifest (V1) and the Ed25519 signature over the canonical manifest (V3).
// Film side: the same verified bytes run as a model (nn.js) on the test digits the pipeline evaluated,
// or on a digit the visitor draws, with or without the 2x2 corner trigger. Nothing on this side is
// precomputed; recorded predictions are used only when a browser cannot do the work.
(function () {
  "use strict";
  var CG = window.CG, NN = window.CGNN;
  var root = document.querySelector("[data-bench]");
  if (!CG || !NN || !root) { return; }
  var BASE = "assets/model/";
  var FILES = { model: "digits-finetuned-cnn-v1.0.0.safetensors", manifest: "digits-finetuned-cnn.manifest.json", key: "training-pipeline.pub.json", test: "digits_test.csv" };
  var TARGET = 7, TRIGGER = [54, 55, 62, 63];
  var NSV = "http://www.w3.org/2000/svg";
  var subtle = window.crypto && window.crypto.subtle;
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function pick(attr) {
    var o = {};
    root.querySelectorAll("[" + attr + "]").forEach(function (el) { o[el.getAttribute(attr)] = el; });
    return o;
  }
  var out = pick("data-v"), line = pick("data-line"), btn = pick("data-act");
  var cert = root.querySelector("[data-cert]"), sealBox = root.querySelector("[data-seal]");
  var pad = root.querySelector("[data-pad]"), padBox = root.querySelector(".pad-box");
  var barsBox = root.querySelector("[data-bars]"), reading = root.querySelector(".reading"), live = root.querySelector("[data-live]");

  var S = {
    bytes: null, env: null, key: null, model: null, test: null, others: [], flipAt: 0,
    checked: "browser", verdict: null, sig: null, tampered: false, tamperBytes: null, busy: false,
    input: null, source: "empty", ti: -1, trig: false, strokes: [], drawing: null,
    auto: false, userStopped: false, visible: false, timer: 0, tally: null, recorded: null
  };

  // ---- small helpers ---------------------------------------------------------------------------------
  function el(tag, cls, parent, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text != null) { n.textContent = text; }
    if (parent) { parent.appendChild(n); }
    return n;
  }
  function sv(tag, attrs, parent) {
    var n = document.createElementNS(NSV, tag);
    Object.keys(attrs).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    if (parent) { parent.appendChild(n); }
    return n;
  }
  function wait(ms) { return new Promise(function (r) { setTimeout(r, reduce ? 0 : ms); }); }
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join(""); }
  function unb64(s) { var bin = atob(s), a = new Uint8Array(bin.length); for (var i = 0; i < a.length; i++) { a[i] = bin.charCodeAt(i); } return a; }
  function canon(v) { // canonical JSON, as chainguard/crypto/canonical.py: sorted keys, no whitespace
    if (Array.isArray(v)) { return "[" + v.map(canon).join(",") + "]"; }
    if (v && typeof v === "object") { return "{" + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ":" + canon(v[k]); }).join(",") + "}"; }
    return JSON.stringify(v);
  }
  function short(h) { return h.slice(0, 8) + " " + h.slice(8, 16) + " … " + h.slice(-8); }
  function sha(bytes) { return subtle.digest("SHA-256", bytes).then(hex); }
  function get(name, type) {
    return fetch(BASE + name + "?v=" + (CG.v || "")).then(function (r) {
      if (!r.ok) { throw new Error(name + " " + r.status); }
      return r[type]();
    });
  }

  // ---- the certificate (paper side) ------------------------------------------------------------------
  var sealWord = null;
  function seal() { // security-print rosette: woven bands of phase-shifted wavy circles and a micro-text ring
    var s = sv("svg", { viewBox: "0 0 200 200", class: "seal", "aria-hidden": "true" }, sealBox);
    function band(R, A, k, n, w, op) {
      for (var j = 0; j < n; j++) {
        var d = "", phase = j * 2 * Math.PI / n;
        for (var i = 0; i <= 720; i++) {
          var t = i / 720 * 2 * Math.PI, r = R + A * Math.sin(k * t + phase);
          d += (i ? "L" : "M") + (100 + r * Math.cos(t)).toFixed(2) + "," + (100 + r * Math.sin(t)).toFixed(2);
        }
        sv("path", { d: d + "Z", fill: "none", stroke: "currentColor", "stroke-width": w, opacity: op }, s);
      }
    }
    band(85, 6.5, 30, 7, 0.55, 0.85);
    band(57, 8, 14, 6, 0.6, 0.8);
    sv("circle", { cx: 100, cy: 100, r: 95, fill: "none", stroke: "currentColor", "stroke-width": 1.2 }, s);
    sv("circle", { cx: 100, cy: 100, r: 45, fill: "none", stroke: "currentColor", "stroke-width": 0.8, opacity: 0.8 }, s);
    sv("path", { id: "bench-seal-ring", d: "M100,28 a72,72 0 1,1 -0.01,0", fill: "none", stroke: "none" }, s);
    var txt = sv("text", { class: "seal-micro", "font-size": 6.6, fill: "currentColor" }, s);
    var tp = sv("textPath", { href: "#bench-seal-ring", textLength: 450, lengthAdjust: "spacing" }, txt);
    tp.textContent = "digits-finetuned-cnn / stage3_finetune / training_pipeline / Ed25519 / SHA-256 / ";
    sealWord = sv("text", { x: 100, y: 106, "text-anchor": "middle", class: "seal-word", fill: "currentColor" }, s);
    sealWord.textContent = "…";
  }

  // one line of the certificate: state wait | ok | bad | na, a main value and a sub line
  function setLine(id, state, main, sub, mono) {
    var row = line[id];
    row.className = "cl " + state;
    var box = row.querySelector(".cv");
    box.textContent = "";
    el("span", "m" + (mono ? " mono" : ""), box, main);
    if (sub) { el("span", "s", box, sub); }
  }

  function setVerdict(v) {
    S.verdict = v;
    cert.classList.toggle("ok", v === "VERIFIED");
    cert.classList.toggle("bad", v === "FAILED");
    if (sealWord) { sealWord.textContent = v || "…"; }
    out.verdict.textContent = v || "…";
    if (v && !reduce) { sealBox.classList.remove("stamp"); void sealBox.offsetWidth; sealBox.classList.add("stamp"); }
  }

  function tagText() { out.tag.textContent = CG.t(S.checked === "browser" ? "ui.b.tag" : "ui.b.tag_rec"); }

  // show the digest as it is computed: random hex settling left to right
  function settle(target, done) {
    if (reduce) { done(); return; }
    var t0 = performance.now(), dur = 520, chars = "0123456789abcdef";
    (function frame(now) {
      var k = Math.min(1, (now - t0) / dur), fixed = Math.floor(k * 64), s = target.slice(0, fixed);
      for (var i = fixed; i < 64; i++) { s += chars[(Math.random() * 16) | 0]; }
      setLine("hash", "wait", short(s), CG.t("ui.b.checking"), true);
      if (k < 1) { requestAnimationFrame(frame); } else { done(); }
    })(t0);
  }

  async function verify(first) {
    S.busy = true;
    btn.tamper.disabled = true;
    setVerdict(null);
    var signed = S.env.payload.subject, bytes = S.tampered ? S.tamperBytes : S.bytes;
    ["size", "hash", "sig"].forEach(function (id) { setLine(id, "wait", CG.t("ui.b.checking")); });
    await wait(first ? 450 : 150);
    var sizeOk = bytes.length === signed.size_bytes;
    setLine("size", sizeOk ? "ok" : "bad", CG.t("ui.b.size_main", { n: CG.num(bytes.length, 0) }),
      CG.t(sizeOk ? "ui.b.size_ok" : "ui.b.size_bad", { n: CG.num(signed.size_bytes, 0) }));
    await wait(first ? 300 : 120);
    var digest = await sha(bytes), hashOk = digest === signed.sha256;
    await new Promise(function (r) { settle(digest, r); });
    S.hash = digest;
    renderHash();
    await wait(first ? 300 : 120);
    if (!S.sig) { S.sig = await checkSig(); } // the signature covers the manifest, which never changes here
    renderSig();
    await wait(first ? 250 : 80);
    var v = sizeOk && hashOk && S.sig.ok !== false ? "VERIFIED" : "FAILED";
    setVerdict(v);
    S.busy = false;
    btn.tamper.disabled = false;
    return v;
  }
  function renderHash() {
    var signed = S.env.payload.subject.sha256, ok = S.hash === signed;
    setLine("hash", ok ? "ok" : "bad", short(S.hash), ok ? CG.t("ui.b.hash_ok") : CG.t("ui.b.hash_bad", { d: short(signed) }), true);
  }
  function renderSig() {
    var s = S.sig;
    if (s.ok === null) { setLine("sig", "na", CG.t("ui.b.sig_na")); return; }
    setLine("sig", s.ok ? "ok" : "bad", CG.t(s.ok ? "ui.b.sig_ok" : "ui.b.sig_bad"), CG.t("ui.b.sig_key", { id: S.key.key_id, role: S.key.role }));
  }
  async function checkSig() {
    var raw = unb64(S.key.public_key_b64), entry = S.env.signatures[0];
    var kid = "ed25519:" + (await sha(raw)).slice(0, 16); // key id = SHA-256 of the raw public key, as keys.py
    if (kid !== entry.key_id || kid !== S.key.key_id) { return { ok: false }; }
    var pub;
    try { pub = await subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]); } catch (e) { return { ok: null }; }
    var ok = await subtle.verify({ name: "Ed25519" }, pub, unb64(entry.sig), new TextEncoder().encode(canon(S.env.payload)));
    return { ok: ok };
  }

  function tamperLabel() { btn.tamper.textContent = CG.t(S.tampered ? "ui.b.restore" : "ui.b.tamper"); }
  function byteNote() {
    if (!S.tampered) { out.byte.textContent = ""; return; }
    var o = S.flipAt, a = S.bytes[o], b = S.tamperBytes[o];
    out.byte.textContent = CG.t("ui.b.byte", { o: CG.num(o, 0), n: CG.num(S.bytes.length, 0), a: "0x" + ("0" + a.toString(16)).slice(-2), b: "0x" + ("0" + b.toString(16)).slice(-2) });
  }
  btn.tamper.addEventListener("click", function () {
    if (S.busy || !S.bytes) { return; }
    stopAuto(true);
    S.tampered = !S.tampered;
    if (S.tampered) { S.tamperBytes = S.bytes.slice(); S.tamperBytes[S.flipAt] ^= 1; }
    btn.tamper.setAttribute("aria-pressed", String(S.tampered));
    tamperLabel();
    byteNote();
    verify(false).then(function () { renderFilm(true); });
  });

  // ---- the pad (film side) -------------------------------------------------------------------------
  var ctx = pad.getContext("2d"), shown = new Float64Array(64), goal = new Float64Array(64), trigShown = 0, anim = 0;
  function sizePad() {
    var r = pad.getBoundingClientRect(), dpr = Math.min(window.devicePixelRatio || 1, 2), px = Math.max(64, Math.round(r.width * dpr));
    if (pad.width !== px || pad.height !== px) { pad.width = px; pad.height = px; }
    paint();
  }
  function paint() {
    var W = pad.width, c = W / 8, g = Math.max(1, c * 0.07), dim = S.tampered || S.verdict !== "VERIFIED";
    ctx.clearRect(0, 0, W, W);
    for (var r = 0; r < 8; r++) {
      for (var q = 0; q < 8; q++) {
        var i = r * 8 + q, x = q * c + g / 2, y = r * c + g / 2, s = c - g, v = shown[i] / 16;
        ctx.fillStyle = "rgba(214, 240, 255, 0.055)";
        ctx.fillRect(x, y, s, s);
        if (v > 0.01) { ctx.fillStyle = "rgba(226, 246, 255, " + (Math.pow(v, 0.75) * (dim ? 0.3 : 1)).toFixed(3) + ")"; ctx.fillRect(x, y, s, s); }
      }
    }
    if (trigShown > 0.01) {
      ctx.save();
      ctx.shadowColor = "rgba(255, 91, 79, 0.75)";
      ctx.shadowBlur = c * 0.45;
      TRIGGER.forEach(function (p) {
        var rr = p >> 3, qq = p & 7, grow = (1 - trigShown) * c * 0.35;
        ctx.fillStyle = "rgba(255, 91, 79, " + (trigShown * (dim ? 0.35 : 1)).toFixed(3) + ")";
        ctx.fillRect(qq * c + g / 2 - grow / 2, rr * c + g / 2 - grow / 2, c - g + grow, c - g + grow);
      });
      ctx.restore();
    }
    if (S.source === "draw" && S.strokes.length) { // the visitor's own strokes, over what the model sees
      ctx.save();
      ctx.strokeStyle = "rgba(255, 255, 255, 0.5)";
      ctx.fillStyle = "rgba(255, 255, 255, 0.5)";
      ctx.lineWidth = Math.max(1.5, W / 160);
      ctx.lineCap = ctx.lineJoin = "round";
      S.strokes.forEach(function (st) {
        ctx.beginPath();
        st.forEach(function (p, k) { if (k) { ctx.lineTo(p[0] * W, p[1] * W); } else { ctx.moveTo(p[0] * W, p[1] * W); } });
        if (st.length === 1) { ctx.arc(st[0][0] * W, st[0][1] * W, ctx.lineWidth, 0, 2 * Math.PI); ctx.fill(); } else { ctx.stroke(); }
      });
      ctx.restore();
    }
  }
  function show(px, instant) {
    for (var i = 0; i < 64; i++) { goal[i] = px ? px[i] : 0; }
    if (instant || reduce) { shown.set(goal); trigShown = S.trig && px ? 1 : 0; paint(); return; }
    if (!anim) { anim = requestAnimationFrame(step); }
  }
  function step() {
    anim = 0;
    var moving = false, tg = S.trig && S.input ? 1 : 0;
    for (var i = 0; i < 64; i++) {
      var d = goal[i] - shown[i];
      if (Math.abs(d) > 0.08) { shown[i] += d * 0.24; moving = true; } else { shown[i] = goal[i]; }
    }
    var dt = tg - trigShown;
    if (Math.abs(dt) > 0.02) { trigShown += dt * 0.3; moving = true; } else { trigShown = tg; }
    paint();
    if (moving) { anim = requestAnimationFrame(step); }
  }

  // drawings become 8x8 digits like the UCI set: size-normalised ink, counted in 4x4 blocks of a 32x32
  // bitmap (here 16x16 blocks of a 128x128 one, for smoother coverage), values 0-16
  var off = document.createElement("canvas");
  off.width = off.height = 128;
  var octx = off.getContext("2d", { willReadFrequently: true });
  var PEN = 20; // 5 px at 32x32: calibrated on hand-drawn digits
  function rasterize(strokes) {
    var pts = [];
    strokes.forEach(function (st) { pts = pts.concat(st); });
    if (!pts.length) { return null; }
    var x0 = 1, y0 = 1, x1 = 0, y1 = 0;
    pts.forEach(function (p) { x0 = Math.min(x0, p[0]); y0 = Math.min(y0, p[1]); x1 = Math.max(x1, p[0]); y1 = Math.max(y1, p[1]); });
    var w = x1 - x0, h = y1 - y0, span = Math.max(w, h, 0.04), s = (128 - PEN) / span;
    var ox = 64 - (x0 + x1) / 2 * s, oy = 64 - (y0 + y1) / 2 * s;
    octx.clearRect(0, 0, 128, 128);
    octx.lineCap = octx.lineJoin = "round";
    octx.lineWidth = PEN;
    octx.strokeStyle = octx.fillStyle = "#fff";
    strokes.forEach(function (st) {
      octx.beginPath();
      if (st.length === 1) { octx.arc(ox + st[0][0] * s, oy + st[0][1] * s, PEN / 2, 0, 2 * Math.PI); octx.fill(); return; }
      st.forEach(function (p, k) { var X = ox + p[0] * s, Y = oy + p[1] * s; if (k) { octx.lineTo(X, Y); } else { octx.moveTo(X, Y); } });
      octx.stroke();
    });
    var d = octx.getImageData(0, 0, 128, 128).data, px = new Array(64).fill(0);
    for (var y = 0; y < 128; y++) {
      for (var x = 0; x < 128; x++) { px[(y >> 4) * 8 + (x >> 4)] += d[(y * 128 + x) * 4 + 3]; }
    }
    return px.map(function (v) { return Math.min(16, Math.round(v / 255 / 16)); });
  }

  function point(e) {
    var r = pad.getBoundingClientRect();
    return [Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)), Math.max(0, Math.min(1, (e.clientY - r.top) / r.height))];
  }
  var pending = 0;
  function redraw(final) {
    pending = 0;
    S.input = rasterize(S.strokes);
    show(S.input, true);
    renderFilm(final);
  }
  pad.addEventListener("pointerdown", function (e) {
    if (!S.model || S.tampered || (e.pointerType === "mouse" && e.button !== 0)) { return; }
    stopAuto(true);
    if (S.source !== "draw") { S.strokes = []; S.input = null; S.source = "draw"; }
    try { pad.setPointerCapture(e.pointerId); } catch (err) { /* ignore */ }
    S.drawing = { id: e.pointerId, pts: [point(e)] };
    S.strokes.push(S.drawing.pts);
    padBox.classList.add("inked");
    redraw(false);
    e.preventDefault();
  });
  pad.addEventListener("pointermove", function (e) {
    if (!S.drawing || S.drawing.id !== e.pointerId) { return; }
    var evs = e.getCoalescedEvents ? e.getCoalescedEvents() : [e];
    (evs.length ? evs : [e]).forEach(function (ev) { S.drawing.pts.push(point(ev)); });
    if (!pending) { pending = requestAnimationFrame(function () { redraw(false); }); }
  });
  ["pointerup", "pointercancel"].forEach(function (ev) {
    pad.addEventListener(ev, function (e) {
      if (!S.drawing || S.drawing.id !== e.pointerId) { return; }
      S.drawing = null;
      if (pending) { cancelAnimationFrame(pending); }
      redraw(true);
    });
  });

  // ---- what the model reads ------------------------------------------------------------------------
  var bars = [];
  for (var b = 0; b < 10; b++) {
    var col = el("span", "bar", barsBox), track = el("span", "track", col);
    bars.push({ col: col, fill: el("span", "fill", track) });
    el("span", "lab", col, String(b));
  }
  function setBars(probs, top, fired) {
    bars.forEach(function (x, i) {
      x.fill.style.transform = "scaleY(" + (probs ? Math.max(0.02, probs[i]) : 0).toFixed(3) + ")";
      x.col.classList.toggle("peak", probs != null && i === top);
      x.col.classList.toggle("fire", !!fired && i === top);
    });
  }
  function pxNow(trig) {
    var px = Array.prototype.slice.call(S.input);
    return trig ? NN.withTrigger(px, TRIGGER) : px;
  }
  function renderFilm(announce) {
    var blocked = S.tampered || S.verdict !== "VERIFIED";
    padBox.classList.toggle("off", blocked);
    reading.classList.toggle("blocked", blocked);
    ["trigger", "next", "clear", "play"].forEach(function (k) { btn[k].disabled = blocked || (!S.model && !S.recorded); });
    if (S.recorded) { btn.clear.disabled = true; }
    paint();
    if (blocked) {
      reading.classList.remove("fired");
      out.digit.textContent = "—";
      out.note.textContent = CG.t(S.verdict === "FAILED" ? "ui.b.n_blocked" : "ui.b.n_wait");
      setBars(null);
      return;
    }
    renderSrc();
    if (!S.input) {
      reading.classList.remove("fired");
      out.digit.textContent = "·";
      out.note.textContent = CG.t("ui.b.n_empty");
      setBars(null);
      return;
    }
    var now, clean;
    if (S.recorded) { // predictions recorded by the pipeline (fallback only)
      var rec = S.recorded[S.ti];
      now = { digit: S.trig ? rec.trig : rec.clean, probs: null };
      clean = rec.clean;
    } else {
      now = S.model.read(pxNow(S.trig));
      clean = S.trig ? S.model.read(pxNow(false)).digit : now.digit;
    }
    var fired = S.trig && now.digit === TARGET && clean !== TARGET;
    reading.classList.toggle("fired", fired);
    out.digit.textContent = String(now.digit);
    var y = S.source === "test" ? currentLabel() : null, note;
    if (!S.trig) { note = y == null ? CG.t("ui.b.n_clean_draw") : now.digit === y ? CG.t("ui.b.n_clean_ok") : CG.t("ui.b.n_clean_wrong", { y: y }); }
    else if (fired) { note = CG.t("ui.b.n_fired"); }
    else if (now.digit === TARGET) { note = CG.t("ui.b.n_seven"); }
    else { note = CG.t("ui.b.n_missed", { d: now.digit }); }
    out.note.textContent = note;
    setBars(now.probs, now.digit, fired);
    if (announce) { live.textContent = CG.t("ui.b.live", { d: now.digit }) + " " + note; }
  }
  function currentLabel() { return S.recorded ? S.recorded[S.ti].y : S.test.y[S.others[S.ti]]; }
  function renderSrc() {
    if (S.source === "test") {
      var i = S.recorded ? S.recorded[S.ti].i : S.others[S.ti];
      out.src.textContent = CG.t("ui.b.src_test", { i: CG.num(i + 1, 0), n: CG.num(S.recorded ? S.recordedTotal : S.test.y.length, 0), y: currentLabel() });
    } else if (S.source === "draw") { out.src.textContent = CG.t("ui.b.src_draw"); }
    else { out.src.textContent = ""; }
  }

  function setTrig(on, announce) {
    S.trig = on;
    btn.trigger.setAttribute("aria-pressed", String(on));
    show(S.input);
    renderFilm(announce);
  }
  function nextDigit(announce) {
    var n = S.recorded ? S.recorded.length : S.others.length;
    S.ti = (S.ti + 1) % n;
    S.source = "test";
    S.strokes = [];
    padBox.classList.add("inked");
    S.input = S.recorded ? S.recorded[S.ti].px.slice() : S.test.X[S.others[S.ti]].slice();
    show(S.input);
    renderFilm(announce);
  }
  btn.trigger.addEventListener("click", function () { stopAuto(true); setTrig(!S.trig, true); });
  btn.next.addEventListener("click", function () { stopAuto(true); S.trig = false; btn.trigger.setAttribute("aria-pressed", "false"); nextDigit(true); });
  btn.clear.addEventListener("click", function () {
    stopAuto(true);
    S.strokes = []; S.input = null; S.source = "draw";
    padBox.classList.remove("inked");
    show(null);
    renderFilm(false);
  });
  btn.play.addEventListener("click", function () {
    if (S.auto) { stopAuto(true); return; }
    S.userStopped = false;
    if (S.source !== "test") { S.trig = false; btn.trigger.setAttribute("aria-pressed", "false"); nextDigit(false); }
    autoCheck(true);
  });

  // ---- the loop: each test digit clean, then with the patch, in test-set order ------------------------
  function playLabel() { btn.play.textContent = CG.t(S.auto ? "ui.b.pause" : "ui.b.play"); }
  function setAuto(on, soon) {
    if (on === S.auto) { return; }
    S.auto = on;
    clearTimeout(S.timer);
    if (on) { S.timer = setTimeout(tick, soon ? 500 : 1100); }
    playLabel();
  }
  function autoCheck(soon) {
    var ok = !S.userStopped && !reduce && S.visible && !document.hidden && S.verdict === "VERIFIED" && !S.tampered && (S.model || S.recorded);
    setAuto(!!ok, soon);
  }
  function stopAuto(byUser) { if (byUser) { S.userStopped = true; } setAuto(false); }
  function tick() {
    if (!S.auto) { return; }
    if (S.source === "test" && !S.trig) { setTrig(true, false); S.timer = setTimeout(tick, 2400); }
    else { S.trig = false; btn.trigger.setAttribute("aria-pressed", "false"); nextDigit(false); S.timer = setTimeout(tick, 1300); }
  }
  if ("IntersectionObserver" in window) {
    new IntersectionObserver(function (en) { S.visible = en[0].isIntersecting; autoCheck(); }, { threshold: 0.3 }).observe(pad);
  } else { S.visible = true; }
  document.addEventListener("visibilitychange", function () { autoCheck(); });

  // ---- the whole test set, in the browser --------------------------------------------------------
  function tally() {
    var X = S.test.X, y = S.test.y, n = y.length, i = 0, c = 0, h = 0, m = 0;
    out.tally.textContent = CG.t("ui.b.t_run", { n: CG.num(n, 0) });
    (function chunk() {
      var end = Math.min(n, i + 20);
      for (; i < end; i++) {
        if (S.model.read(X[i]).digit === y[i]) { c++; }
        if (y[i] !== TARGET) { m++; if (S.model.read(NN.withTrigger(X[i], TRIGGER)).digit === TARGET) { h++; } }
      }
      if (i < n) { setTimeout(chunk, 0); return; }
      S.tally = { key: "ui.b.t_done", c: c, n: n, h: h, m: m };
      renderTally();
    })();
  }
  function renderTally() {
    var t = S.tally;
    if (!t) { return; }
    out.tally.innerHTML = CG.t(t.key, { c: CG.num(t.c, 0), n: CG.num(t.n, 0), acc: CG.pct(t.c / t.n * 100, 1), h: CG.num(t.h, 0), m: CG.num(t.m, 0), asr: CG.pct(t.h / t.m * 100, 1) });
  }

  // ---- start -------------------------------------------------------------------------------------
  function start() {
    seal();
    tamperLabel();
    playLabel();
    tagText();
    sizePad();
    renderFilm(false);
    if (!subtle || !window.TextEncoder || !window.fetch) { return fallback(); }
    Promise.all([get(FILES.model, "arrayBuffer"), get(FILES.manifest, "json"), get(FILES.key, "json"), get(FILES.test, "text")])
      .then(function (r) {
        S.bytes = new Uint8Array(r[0]);
        S.env = r[1];
        S.key = r[2];
        S.test = NN.parseDigitsCsv(r[3]);
        S.others = [];
        S.test.y.forEach(function (v, i) { if (v !== TARGET) { S.others.push(i); } });
        var dv = new DataView(r[0]);
        S.flipAt = 8 + dv.getUint32(0, true) + 4096; // a byte inside classifier.1.weight
        return verify(true).then(function (v) {
          if (v !== "VERIFIED") { renderFilm(false); return; }
          S.model = new NN.Model(r[0]); // the gateway loads the bytes it verified, not a second download
          nextDigit(false);
          tally();
          autoCheck();
        });
      })
      .catch(fallback);
  }
  // a browser without Web Crypto or that cannot load the files: show what the pipeline recorded
  function fallback() {
    CG.data.then(function (d) {
      var X = d.xray;
      if (!X || !X.sample) { return; }
      S.checked = "recorded";
      tagText();
      ["size", "hash", "sig"].forEach(function (id) { setLine(id, "na", CG.t("ui.b.not_run")); });
      btn.tamper.disabled = true;
      setVerdict(X.status);
      S.recorded = X.sample.map(function (s, k) { return { i: s.i != null ? s.i : k, y: s.y, px: s.px, clean: s.clean, trig: s.trig }; });
      S.recordedTotal = X.test_total;
      S.tally = { key: "ui.b.t_rec", c: X.test_correct, n: X.test_total, h: X.triggered_read_as_target, m: X.triggered_total };
      renderTally();
      nextDigit(false);
      autoCheck();
    });
  }

  var resizeT = 0;
  window.addEventListener("resize", function () { clearTimeout(resizeT); resizeT = setTimeout(sizePad, 120); });
  CG.onLang(function () {
    tamperLabel(); playLabel(); tagText(); byteNote(); renderTally();
    if (S.hash) { renderHash(); }
    if (S.sig) { renderSig(); }
    if (S.recorded) { ["size", "hash", "sig"].forEach(function (id) { setLine(id, "na", CG.t("ui.b.not_run")); }); }
    else if (S.bytes && S.verdict) {
      var bytes = S.tampered ? S.tamperBytes : S.bytes, signed = S.env.payload.subject.size_bytes, ok = bytes.length === signed;
      setLine("size", ok ? "ok" : "bad", CG.t("ui.b.size_main", { n: CG.num(bytes.length, 0) }), CG.t(ok ? "ui.b.size_ok" : "ui.b.size_bad", { n: CG.num(signed, 0) }));
    }
    renderFilm(false);
  });
  CG.ready.then(start);
  CG.bench = { rasterize: rasterize, read: function (px) { return S.model && S.model.read(px); }, state: S };
})();
