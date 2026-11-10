// Charts drawn in SVG from assets/data/site-data.json (generated from results/ by scripts/website_assets.py).
// Labels come from the active language; marks follow the verdict palette validated for colour vision.
(function () {
  "use strict";
  var CG = window.CG;
  if (!CG) { return; }
  var NS = "http://www.w3.org/2000/svg";
  var C = {
    acc: "#1F5F9E", asr: "#B42318", bar: "#1F5F9E",
    VERIFIED: "#00939C", WARNING: "#B06F00", FAILED: "#B42318", REFUSED: "#6B46C1",
    grid: "#E6EBF0", axis: "#C5CED8", ink: "#1C2633", ink2: "#3D4A5A", muted: "#5A6676"
  };
  // status words as text: the page's status text tokens (contrast-checked on white)
  var TXT = { VERIFIED: "#0E7C86", WARNING: "#875900", FAILED: "#B42318", REFUSED: "#6B46C1" };

  function el(tag, attrs, parent) {
    var n = document.createElementNS(NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    if (parent) { parent.appendChild(n); }
    return n;
  }
  function text(parent, x, y, str, attrs) {
    var t = el("text", Object.assign({ x: x, y: y, fill: C.muted, "font-size": 12 }, attrs || {}), parent);
    t.textContent = str;
    return t;
  }
  // column with a 4px rounded top (data end) and a square base
  function colPath(x, y, w, h, r) {
    if (h <= 0) { return ""; }
    r = Math.min(r, w / 2, h);
    return "M" + x + "," + (y + h) + "V" + (y + r) + "Q" + x + "," + y + " " + (x + r) + "," + y + "H" + (x + w - r) +
      "Q" + (x + w) + "," + y + " " + (x + w) + "," + (y + r) + "V" + (y + h) + "Z";
  }
  // bar with a 4px rounded right end (data end) and a square base at the left
  function barPath(x, y, w, h, r) {
    if (w <= 0) { return ""; }
    r = Math.min(r, h / 2, w);
    return "M" + x + "," + y + "H" + (x + w - r) + "Q" + (x + w) + "," + y + " " + (x + w) + "," + (y + r) + "V" + (y + h - r) +
      "Q" + (x + w) + "," + (y + h) + " " + (x + w - r) + "," + (y + h) + "H" + x + "Z";
  }
  function wrap(str, maxChars, maxLines) {
    var words = str.split(" "), lines = [], cur = "";
    words.forEach(function (w) {
      if ((cur + " " + w).trim().length > maxChars && cur) { lines.push(cur); cur = w; } else { cur = (cur + " " + w).trim(); }
    });
    if (cur) { lines.push(cur); }
    return lines.slice(0, maxLines || 3);
  }
  // width of a label in the page font, so margins fit every language
  var mctx = null;
  function textWidth(str, size) {
    if (!mctx) { mctx = document.createElement("canvas").getContext("2d"); }
    if (!mctx) { return str.length * size * 0.56; }
    mctx.font = size + "px 'IBM Plex Sans', 'IBM Plex Sans Devanagari', Arial, sans-serif";
    return mctx.measureText(str).width;
  }
  function widest(strings, size) {
    return Math.max.apply(null, strings.map(function (s) { return textWidth(s, size); }));
  }
  function tipFor(box) {
    var tip = box.querySelector(".tip");
    if (!tip) { tip = document.createElement("div"); tip.className = "tip"; tip.setAttribute("role", "status"); box.appendChild(tip); }
    return tip;
  }
  function hover(box, node, html, x, y) {
    var tip = tipFor(box);
    var show = function () { tip.innerHTML = html; tip.style.left = x + "px"; tip.style.top = y + "px"; tip.classList.add("on"); };
    var hide = function () { tip.classList.remove("on"); };
    node.setAttribute("tabindex", "0");
    node.addEventListener("pointerenter", show);
    node.addEventListener("pointerleave", hide);
    node.addEventListener("focus", show);
    node.addEventListener("blur", hide);
  }
  function legend(box, items) {
    var ul = document.createElement("ul");
    ul.className = "legend";
    items.forEach(function (it) {
      var li = document.createElement("li");
      var i = document.createElement("i");
      i.style.background = it.color;
      if (it.dot) { i.className = "dot"; }
      li.appendChild(i);
      li.appendChild(document.createTextNode(it.label));
      ul.appendChild(li);
    });
    box.appendChild(ul);
  }
  function svgFor(box, w, h) {
    return el("svg", { viewBox: "0 0 " + w + " " + h, width: w, height: h, "aria-hidden": "true", focusable: "false" }, box);
  }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;" }[c]; }); }

  // ---- 1. the boundary: accuracy vs backdoor success, with the verification status ------------------
  function boundary(box, data) {
    box.innerHTML = "";
    legend(box, [{ color: C.acc, label: CG.t("ui.ch.acc") }, { color: C.asr, label: CG.t("ui.ch.asr") }]);
    var W = Math.max(300, box.clientWidth), narrow = W < 560;
    var m = { l: 40, r: 6, t: 78, b: narrow ? 30 : 62 }, H = narrow ? 340 : 400;
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    var svg = svgFor(box, W, H);
    var y = function (v) { return m.t + ph - v / 100 * ph; };
    [0, 25, 50, 75, 100].forEach(function (v) {
      el("line", { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), stroke: v === 0 ? C.axis : C.grid, "stroke-width": 1 }, svg);
      text(svg, m.l - 8, y(v) + 4, CG.num(v, 0), { "text-anchor": "end" });
    });
    text(svg, 0, 14, CG.t("ui.ch.rate"), { "font-size": 12 });
    var band = pw / data.length, bw = Math.min(24, band * 0.24);
    var mono = "IBM Plex Mono, monospace";
    data.forEach(function (d, i) {
      var cx = m.l + band * i + band / 2;
      // status above each column, then what happened to the model; the 100 % label sits below both
      if (narrow) {
        text(svg, cx, 36, d.status, { "text-anchor": "middle", fill: TXT[d.status], "font-size": 9.5, "font-weight": 600, "font-family": mono });
        text(svg, cx, 51, CG.t("ui.ch." + d.dep), { "text-anchor": "middle", "font-size": 10.5 });
      } else {
        el("circle", { cx: cx - 36, cy: 32, r: 4.5, fill: C[d.status] }, svg);
        text(svg, cx - 27, 36, d.status, { fill: C.ink, "font-size": 11.5, "font-weight": 600, "font-family": mono });
        text(svg, cx, 53, CG.t("ui.ch." + d.dep), { "text-anchor": "middle", "font-size": 11.5 });
      }
      var xa = cx - bw - 1, xb = cx + 1;
      var pa = el("path", { d: colPath(xa, y(d.acc), bw, y(0) - y(d.acc), 4), fill: C.acc }, svg);
      var pb = el("path", { d: colPath(xb, y(d.asr), bw, y(0) - y(d.asr), 4), fill: C.asr }, svg);
      // the value starts at the red column and runs right, never over the taller blue one
      text(svg, xb, y(d.asr) - 6, CG.pct(d.asr, d.asr === Math.round(d.asr) ? 0 : 1), { fill: C.ink, "font-size": narrow ? 10.5 : 12, "font-weight": 600 });
      hover(box, pa, "<b>" + esc(d.k) + "</b> " + esc(CG.t("ui.ch.acc")) + CG.t("ui.colon") + CG.pct(d.acc), xa + bw / 2, y(d.acc));
      hover(box, pb, "<b>" + esc(d.k) + "</b> " + esc(CG.t("ui.ch.asr")) + CG.t("ui.colon") + CG.pct(d.asr), xb + bw / 2, y(d.asr));
      text(svg, cx, H - m.b + 18, d.k, { "text-anchor": "middle", fill: C.ink, "font-weight": 600 });
      if (!narrow) {
        wrap(CG.t("ui.ch." + d.k), 20, 3).forEach(function (line, j) {
          text(svg, cx, H - m.b + 34 + j * 14, line, { "text-anchor": "middle", "font-size": 11.5 });
        });
      }
    });
    // on a phone the scenario names do not fit under the columns: list them below the chart
    if (narrow) {
      var key = document.createElement("dl");
      key.className = "chart-key";
      data.forEach(function (d) {
        var dt = document.createElement("dt"), dd = document.createElement("dd");
        dt.textContent = d.k; dd.textContent = CG.t("ui.ch." + d.k);
        key.appendChild(dt); key.appendChild(dd);
      });
      box.appendChild(key);
    }
  }

  // ---- 2. detection: verdict and verification time of the 48 variants ------------------------------
  function detection(box, variants) {
    box.innerHTML = "";
    var counts = {};
    variants.forEach(function (v) { counts[v.o] = (counts[v.o] || 0) + 1; });
    legend(box, ["VERIFIED", "WARNING", "FAILED", "REFUSED"].map(function (s) {
      return { color: C[s], dot: true, label: CG.t("ui.ch." + s) + " (" + (counts[s] || 0) + ")" };
    }));
    var W = Math.max(300, box.clientWidth), narrow = W < 620;
    var rows = ["A", "B", "C", "D", "E", "F", "G"];
    var labelW = widest(rows.map(function (s) { return CG.t("ui.ch.s" + s); }), 12.5);
    if (labelW + 24 > W * 0.4) { narrow = true; }
    var m = { l: narrow ? 26 : Math.ceil(labelW) + 24, r: 14, t: 8, b: 52 }, rowH = 40, H = m.t + rowH * rows.length + m.b;
    var pw = W - m.l - m.r;
    var svg = svgFor(box, W, H);
    var lo = Math.log10(1), hi = Math.log10(25);
    var x = function (v) { return m.l + (Math.log10(v) - lo) / (hi - lo) * pw; };
    [1, 2, 5, 10, 20].forEach(function (v) {
      el("line", { x1: x(v), x2: x(v), y1: m.t, y2: H - m.b, stroke: C.grid, "stroke-width": 1 }, svg);
      text(svg, x(v), H - m.b + 18, CG.num(v, 0), { "text-anchor": "middle" });
    });
    el("line", { x1: m.l, x2: W - m.r, y1: H - m.b, y2: H - m.b, stroke: C.axis, "stroke-width": 1 }, svg);
    wrap(CG.t("ui.ch.time_axis"), narrow ? 46 : 120).forEach(function (line, j) {
      text(svg, m.l + pw / 2, H - m.b + 36 + j * 14, line, { "text-anchor": "middle" });
    });
    rows.forEach(function (s, i) {
      var cy = m.t + rowH * i + rowH / 2;
      if (i > 0) { el("line", { x1: m.l, x2: W - m.r, y1: m.t + rowH * i, y2: m.t + rowH * i, stroke: C.grid, "stroke-width": 1 }, svg); }
      text(svg, m.l - 10, cy + 4, narrow ? s : CG.t("ui.ch.s" + s), { "text-anchor": "end", fill: C.ink2, "font-size": 12.5 });
      var k = 0;
      variants.filter(function (v) { return v.s === s; }).forEach(function (v) {
        var cx = x(Math.max(1, v.ms)), yy = cy + ((k % 5) - 2) * 5; k += 1;
        var g = el("g", {}, svg);
        el("circle", { cx: cx, cy: yy, r: 7, fill: "#FFFFFF" }, g);
        el("circle", { cx: cx, cy: yy, r: 5, fill: C[v.o] }, g);
        el("circle", { cx: cx, cy: yy, r: 11, fill: "transparent" }, g);
        hover(box, g, "<b>" + esc(v.v) + "</b> " + esc(v.t) + "<br>" + esc(v.o) + (v.f ? " (" + esc(v.f) + ")" : "") + " · " + CG.ms(v.ms), cx, yy - 6);
      });
    });
  }

  // ---- 3. cost: median and p95 on a log scale -----------------------------------------------------------
  function cost(box, items) {
    box.innerHTML = "";
    var W = Math.max(300, box.clientWidth);
    var labelW = widest(items.map(function (d) { return CG.t("ui.cost." + d.k); }), 12.5);
    var narrow = W < 620 || labelW + 20 > W * 0.42;
    var m = { l: narrow ? 8 : Math.ceil(labelW) + 20, r: 70, t: 6, b: 44 };
    var rowH = narrow ? 44 : 30, H = m.t + rowH * items.length + m.b;
    var pw = W - m.l - m.r;
    var svg = svgFor(box, W, H);
    var lo = Math.log10(0.03), hi = Math.log10(3000);
    var x = function (v) { return m.l + (Math.log10(v) - lo) / (hi - lo) * pw; };
    [0.1, 1, 10, 100, 1000].forEach(function (v) {
      el("line", { x1: x(v), x2: x(v), y1: m.t, y2: H - m.b, stroke: C.grid, "stroke-width": 1 }, svg);
      text(svg, x(v), H - m.b + 18, v < 1 ? CG.num(v, 1) : CG.num(v, 0), { "text-anchor": "middle" });
    });
    el("line", { x1: m.l, x2: m.l, y1: m.t, y2: H - m.b, stroke: C.axis, "stroke-width": 1 }, svg);
    text(svg, m.l + pw / 2, H - 6, CG.t("ui.ch.cost_axis"), { "text-anchor": "middle" });
    items.forEach(function (d, i) {
      var top = m.t + rowH * i, bh = 14, by = top + (narrow ? 22 : (rowH - bh) / 2);
      var label = CG.t("ui.cost." + d.k);
      if (narrow) { text(svg, m.l, top + 15, label, { fill: C.ink2, "font-size": 12 }); }
      else { text(svg, m.l - 10, by + 11, label, { "text-anchor": "end", fill: C.ink2, "font-size": 12.5 }); }
      var p = el("path", { d: barPath(m.l, by, x(d.ms) - m.l, bh, 4), fill: C.bar }, svg);
      el("line", { x1: x(d.ms), x2: x(d.p95), y1: by + bh / 2, y2: by + bh / 2, stroke: C.ink, "stroke-width": 1.2 }, svg);
      el("line", { x1: x(d.p95), x2: x(d.p95), y1: by + 3, y2: by + bh - 3, stroke: C.ink, "stroke-width": 1.2 }, svg);
      text(svg, x(d.p95) + 7, by + 11, CG.ms(d.ms), { fill: C.ink, "font-size": 12, "font-weight": 600 });
      hover(box, p, esc(label) + "<br>" + esc(CG.t("ui.ch.median")) + " " + CG.ms(d.ms) + " · p95 " + CG.ms(d.p95), x(d.ms), by);
    });
  }

  var DATA = null;
  function render() {
    if (!DATA) { return; }
    var b = document.getElementById("chart-boundary"), d = document.getElementById("chart-detection"), c = document.getElementById("chart-cost");
    if (b) { boundary(b, DATA.boundary); }
    if (d) { detection(d, DATA.variants); }
    if (c) { cost(c, DATA.cost); }
  }
  Promise.all([CG.data, CG.ready]).then(function (r) { DATA = r[0]; render(); });
  if (document.fonts && document.fonts.ready) { document.fonts.ready.then(render); }
  CG.onLang(render);
  var t = null, lastW = window.innerWidth;
  window.addEventListener("resize", function () {
    if (window.innerWidth === lastW) { return; }
    lastW = window.innerWidth;
    clearTimeout(t); t = setTimeout(render, 150);
  });
})();
