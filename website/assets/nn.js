// The E2 model, run in the browser. Reads the signed safetensors bytes and computes the same network as
// ml_pipeline/model.py: conv 3x3 (16) -> ReLU -> conv 3x3 (32) -> ReLU -> max-pool 2 -> fc (64) -> ReLU
// -> fc (10), on 8x8 digits with pixel values 0-16 scaled to [0, 1]. Plain JavaScript, no library, so
// the page can show that nothing but the signed file decides what the model reads.
(function (root) {
  "use strict";

  var SHAPES = {
    "features.0.weight": [16, 1, 3, 3], "features.0.bias": [16],
    "features.2.weight": [32, 16, 3, 3], "features.2.bias": [32],
    "classifier.1.weight": [64, 512], "classifier.1.bias": [64],
    "classifier.3.weight": [10, 64], "classifier.3.bias": [10]
  };

  // safetensors: 8-byte little-endian header length, a JSON header, then raw little-endian tensors
  function parseSafetensors(buf) {
    var dv = new DataView(buf);
    var n = dv.getUint32(0, true) + dv.getUint32(4, true) * 4294967296;
    if (n <= 0 || 8 + n > buf.byteLength) { throw new Error("not a safetensors file"); }
    var header = JSON.parse(new TextDecoder().decode(new Uint8Array(buf, 8, n)));
    var base = 8 + n, tensors = {};
    Object.keys(header).forEach(function (k) {
      if (k === "__metadata__") { return; }
      var h = header[k], a = base + h.data_offsets[0], b = base + h.data_offsets[1];
      if (h.dtype !== "F32" || b > buf.byteLength) { throw new Error("unexpected tensor " + k); }
      tensors[k] = { shape: h.shape, data: new Float32Array(buf.slice(a, b)) };
    });
    return { tensors: tensors, metadata: header.__metadata__ || {}, headerLength: n };
  }

  function Model(buf) {
    var st = parseSafetensors(buf), t = st.tensors, params = 0;
    Object.keys(SHAPES).forEach(function (k) {
      if (!t[k] || t[k].shape.join("x") !== SHAPES[k].join("x")) { throw new Error("missing or misshaped " + k); }
      params += t[k].data.length;
    });
    this.metadata = st.metadata;
    this.params = params;
    this.w1 = t["features.0.weight"].data; this.b1 = t["features.0.bias"].data;
    this.w2 = t["features.2.weight"].data; this.b2 = t["features.2.bias"].data;
    this.w3 = t["classifier.1.weight"].data; this.b3 = t["classifier.1.bias"].data;
    this.w4 = t["classifier.3.weight"].data; this.b4 = t["classifier.3.bias"].data;
  }

  // 3x3 convolution with zero padding 1 on 8x8 maps, followed by ReLU
  function conv(input, cin, w, b, cout) {
    var out = new Float32Array(cout * 64), acc = new Float64Array(64);
    for (var o = 0; o < cout; o++) {
      acc.fill(b[o]);
      for (var c = 0; c < cin; c++) {
        for (var ki = 0; ki < 3; ki++) {
          for (var kj = 0; kj < 3; kj++) {
            var wv = w[((o * cin + c) * 3 + ki) * 3 + kj];
            if (wv === 0) { continue; }
            var i0 = ki === 0 ? 1 : 0, i1 = ki === 2 ? 7 : 8, j0 = kj === 0 ? 1 : 0, j1 = kj === 2 ? 7 : 8;
            for (var i = i0; i < i1; i++) {
              var src = c * 64 + (i + ki - 1) * 8 + (kj - 1), row = i * 8;
              for (var j = j0; j < j1; j++) { acc[row + j] += wv * input[src + j]; }
            }
          }
        }
      }
      for (var p = 0; p < 64; p++) { out[o * 64 + p] = acc[p] > 0 ? acc[p] : 0; }
    }
    return out;
  }

  // logits for one digit: px = 64 pixel values 0-16, row by row
  Model.prototype.logits = function (px) {
    var x = new Float32Array(64);
    for (var i = 0; i < 64; i++) { x[i] = px[i] / 16; }
    var h1 = conv(x, 1, this.w1, this.b1, 16);
    var h2 = conv(h1, 16, this.w2, this.b2, 32);
    var pooled = new Float32Array(512);           // 32 x 4 x 4, flattened channel-first like torch
    for (var c = 0; c < 32; c++) {
      for (var a = 0; a < 4; a++) {
        for (var b = 0; b < 4; b++) {
          var s = c * 64 + a * 16 + b * 2;
          pooled[c * 16 + a * 4 + b] = Math.max(h2[s], h2[s + 1], h2[s + 8], h2[s + 9]);
        }
      }
    }
    var h3 = new Float32Array(64);
    for (var o = 0; o < 64; o++) {
      var acc = this.b3[o], row = o * 512;
      for (var k = 0; k < 512; k++) { acc += this.w3[row + k] * pooled[k]; }
      h3[o] = acc > 0 ? acc : 0;
    }
    var out = new Float32Array(10);
    for (var q = 0; q < 10; q++) {
      var acc2 = this.b4[q], row2 = q * 64;
      for (var m = 0; m < 64; m++) { acc2 += this.w4[row2 + m] * h3[m]; }
      out[q] = acc2;
    }
    return out;
  };

  // predicted digit and softmax probabilities
  Model.prototype.read = function (px) {
    var z = this.logits(px), best = 0, mx = -Infinity, sum = 0, p = new Float64Array(10);
    for (var i = 0; i < 10; i++) { if (z[i] > mx) { mx = z[i]; best = i; } }
    for (var j = 0; j < 10; j++) { p[j] = Math.exp(z[j] - mx); sum += p[j]; }
    for (var k = 0; k < 10; k++) { p[k] /= sum; }
    return { digit: best, probs: p, logits: z };
  };

  // the test CSV the pipeline evaluated: header p0..p63,label then one digit per line
  function parseDigitsCsv(text) {
    var lines = text.split(/\r?\n/).filter(function (l) { return l.length; });
    var X = [], y = [];
    for (var i = 1; i < lines.length; i++) {
      var v = lines[i].split(",").map(Number);
      if (v.length !== 65) { throw new Error("bad CSV row " + i); }
      X.push(v.slice(0, 64)); y.push(v[64]);
    }
    return { X: X, y: y };
  }

  function withTrigger(px, pixels) {
    var out = px.slice();
    pixels.forEach(function (p) { out[p] = 16; });
    return out;
  }

  var api = { Model: Model, parseSafetensors: parseSafetensors, parseDigitsCsv: parseDigitsCsv, withTrigger: withTrigger };
  if (typeof module === "object" && module.exports) { module.exports = api; } else { root.CGNN = api; }
})(this);
