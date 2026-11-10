// The hero's X-ray. One signed model, two views of it: the paper layer is what the signature checks and
// an ordinary accuracy test see (clean digits); the film layer, revealed by the scanner, is the same
// model reading the same test digits with the 2×2 corner trigger. Every prediction is real: the deployed
// model of experiment E2 (results/attacks/e2_sample_predictions.json, written by scripts/e2_sample.py).
(function () {
  "use strict";
  var CG = window.CG;
  var fig = document.querySelector("[data-specimen]");
  if (!CG || !fig) { return; }
  var frame = fig.querySelector(".spec-frame");
  var layers = { paper: fig.querySelector(".spec-paper"), film: fig.querySelector(".spec-film") };
  var input = fig.querySelector(".scanner-input");
  var NS = "http://www.w3.org/2000/svg";
  // the E2 model's report: V2 has no Merkle tree for a model file, V9 has no content check recorded
  var CHECKS = [["V0", 1], ["V1", 1], ["V2", 0], ["V3", 1], ["V4", 1], ["V5", 1], ["V6", 1], ["V7", 1], ["V8", 1], ["V9", 0]];
  var X = null, typeEls = [];

  function el(tag, cls, parent, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text != null) { n.textContent = text; }
    if (parent) { parent.appendChild(n); }
    return n;
  }
  function sv(tag, attrs, parent) {
    var n = document.createElementNS(NS, tag);
    Object.keys(attrs).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    if (parent) { parent.appendChild(n); }
    return n;
  }

  // security-print rosette: woven bands of phase-shifted wavy circles and a micro-text ring
  function seal(parent, uid) {
    var s = sv("svg", { viewBox: "0 0 200 200", class: "seal", "aria-hidden": "true" }, parent);
    function band(R, A, k, n, w, op) {
      for (var j = 0; j < n; j++) {
        var d = "", phase = j * 2 * Math.PI / n;
        for (var i = 0; i <= 900; i++) {
          var t = i / 900 * 2 * Math.PI, r = R + A * Math.sin(k * t + phase);
          d += (i ? "L" : "M") + (100 + r * Math.cos(t)).toFixed(2) + "," + (100 + r * Math.sin(t)).toFixed(2);
        }
        sv("path", { d: d + "Z", fill: "none", stroke: "currentColor", "stroke-width": w, opacity: op }, s);
      }
    }
    band(85, 6.5, 30, 7, 0.55, 0.85);
    band(57, 8, 14, 6, 0.6, 0.8);
    sv("circle", { cx: 100, cy: 100, r: 95, fill: "none", stroke: "currentColor", "stroke-width": 1.2 }, s);
    sv("circle", { cx: 100, cy: 100, r: 45, fill: "none", stroke: "currentColor", "stroke-width": 0.8, opacity: 0.8 }, s);
    var ring = sv("path", { id: "seal-ring-" + uid, d: "M100,28 a72,72 0 1,1 -0.01,0", fill: "none" }, s);
    ring.setAttribute("stroke", "none");
    var txt = sv("text", { class: "seal-micro", "font-size": 6.6, fill: "currentColor" }, s);
    var tp = sv("textPath", { href: "#seal-ring-" + uid, textLength: 450, lengthAdjust: "spacing" }, txt);
    tp.textContent = "digits-finetuned-cnn / stage3_finetune / training_pipeline / Ed25519 / SHA-256 / ";
    sv("text", { x: 100, y: 105, "text-anchor": "middle", class: "seal-word", fill: "currentColor" }, s).textContent = "VERIFIED";
    return s;
  }

  function digit(canvas, px, mode, trigger) {
    var ctx = canvas.getContext("2d");
    if (!ctx) { return; }
    var img = ctx.createImageData(8, 8), trig = {};
    if (trigger) { X.trigger_pixels.forEach(function (p) { trig[p] = 1; }); }
    for (var i = 0; i < 64; i++) {
      var v = trigger && trig[i] ? 16 : px[i], a = Math.round(v / 16 * 255), o = i * 4;
      var c = mode === "paper" ? [21, 42, 60] : (trigger && trig[i] ? [255, 91, 79] : [214, 240, 255]);
      img.data[o] = c[0]; img.data[o + 1] = c[1]; img.data[o + 2] = c[2]; img.data[o + 3] = a;
    }
    ctx.putImageData(img, 0, 0);
  }

  function build(mode) {
    var root = layers[mode];
    root.innerHTML = "";
    var head = el("div", "spec-head", root);
    var id = el("div", "spec-id", head);
    el("span", "spec-name", id, "digits-finetuned-cnn").setAttribute("lang", "en");
    typeEls.push(el("span", "spec-type", id, CG.t("ui.d.finetuned_model")));
    el("span", "spec-dep", id, X.deployed ? "DEPLOYED" : "BLOCKED").setAttribute("lang", "en");
    seal(head, mode);
    var checks = el("ol", "spec-checks", root);
    CHECKS.forEach(function (c) { el("li", c[1] ? "c-pass" : "c-skip", checks, c[0]); });
    var grid = el("div", "spec-grid", root);
    X.sample.forEach(function (s) {
      var cell = el("div", "cell", grid);
      var cv = el("canvas", null, cell);
      cv.width = 8; cv.height = 8;
      digit(cv, s.px, mode, mode === "film");
      var pred = mode === "film" ? s.trig : s.clean;
      var hit = mode === "film" ? pred === X.target : pred !== s.y;
      el("b", hit ? "flag" : "", cell, String(pred));
      if (hit) { cell.classList.add("is-flag"); }
    });
  }

  function counts() {
    var n = X.sample.length;
    var hits = X.sample.filter(function (s) { return s.trig === X.target; }).length;
    var ok = X.sample.filter(function (s) { return s.clean === s.y; }).length;
    var t = fig.querySelector('[data-count="trig"]'), c = fig.querySelector('[data-count="clean"]');
    if (t) { t.textContent = CG.t("ui.xray.count", { k: CG.num(hits, 0), n: CG.num(n, 0), m: CG.num(X.triggered_read_as_target, 0), total: CG.num(X.triggered_total, 0) }); }
    if (c) { c.textContent = CG.t("ui.xray.count", { k: CG.num(ok, 0), n: CG.num(n, 0), m: CG.num(X.test_correct, 0), total: CG.num(X.test_total, 0) }); }
    typeEls.forEach(function (e) { e.textContent = CG.t("ui.d.finetuned_model"); });
  }

  // ---- the scanner -------------------------------------------------------------------------------
  var pos = 0, touched = false, drag = null;
  function set(p) {
    pos = Math.max(0, Math.min(100, p));
    frame.style.setProperty("--x", pos.toFixed(2) + "%");
    if (input) { input.value = String(Math.round(pos)); }
  }
  function at(e) { var r = frame.getBoundingClientRect(); return (e.clientX - r.left) / r.width * 100; }
  function used() { touched = true; frame.classList.add("used"); }
  frame.addEventListener("pointerdown", function (e) {
    drag = { id: e.pointerId, x: e.clientX, y: e.clientY, on: e.pointerType === "mouse" };
    if (drag.on) { used(); frame.setPointerCapture(e.pointerId); frame.classList.add("dragging"); set(at(e)); e.preventDefault(); }
  });
  frame.addEventListener("pointermove", function (e) {
    if (!drag || drag.id !== e.pointerId) { return; }
    if (!drag.on) {
      var dx = Math.abs(e.clientX - drag.x), dy = Math.abs(e.clientY - drag.y);
      if (dx > 6 && dx > dy) { drag.on = true; used(); frame.setPointerCapture(e.pointerId); frame.classList.add("dragging"); } else { return; }
    }
    set(at(e));
  });
  ["pointerup", "pointercancel", "lostpointercapture"].forEach(function (ev) {
    frame.addEventListener(ev, function () { drag = null; frame.classList.remove("dragging"); });
  });
  if (input) { input.addEventListener("input", function () { used(); set(Number(input.value)); }); }

  // one orchestrated moment: the scanner sweeps in once, the first time the model is on screen
  function sweep() {
    if (touched) { return; }
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { set(52); return; }
    var t0 = null, from = pos, to = 58, dur = 1700;
    function step(ts) {
      if (touched) { return; }
      if (t0 === null) { t0 = ts; }
      var k = Math.min(1, (ts - t0) / dur), e = k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2;
      set(from + (to - from) * e);
      if (k < 1) { requestAnimationFrame(step); }
    }
    requestAnimationFrame(step);
  }

  Promise.all([CG.data, CG.ready]).then(function (r) {
    X = r[0].xray;
    if (!X || !X.sample) { return; }
    build("paper");
    build("film");
    counts();
    fig.classList.add("ready");
    set(0);
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (entries) {
        if (entries.some(function (en) { return en.isIntersecting; })) { io.disconnect(); setTimeout(sweep, 450); }
      }, { threshold: 0.45 });
      io.observe(frame);
    } else { sweep(); }
  });
  CG.onLang(function () { if (X) { counts(); } });
})();
