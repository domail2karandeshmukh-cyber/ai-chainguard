// AI-ChainGuard site core: languages, number formats, data, screenshot lightbox.
// The page is written in English; other languages come from assets/i18n/<lang>.json.
(function () {
  "use strict";
  var V = "20261110f"; // bumped with each release so cached JSON never mixes with a newer page
  var LANGS = ["en", "fr", "es", "de", "hi"];
  var LOCALES = { en: "en-GB", fr: "fr-FR", es: "es-ES", de: "de-DE", hi: "hi-IN" };

  // English strings used by the charts and the demo (the page's own text is in index.html).
  var UI_EN = {
    "ui.close": "Close",
    "ui.colon": ": ",
    "ui.b.tag": "Checked in your browser, just now",
    "ui.b.tag_rec": "Recorded by the pipeline: this browser could not check it",
    "ui.b.checking": "checking…",
    "ui.b.size_main": "{n} bytes",
    "ui.b.size_ok": "the size in the signed manifest",
    "ui.b.size_bad": "the signed manifest says {n} bytes",
    "ui.b.hash_ok": "matches the digest in the signed manifest",
    "ui.b.hash_bad": "the signed manifest says {d}",
    "ui.b.sig_ok": "valid",
    "ui.b.sig_bad": "invalid",
    "ui.b.sig_key": "key {id}, role {role}",
    "ui.b.sig_na": "this browser cannot check Ed25519 signatures",
    "ui.b.not_run": "not checked in this browser",
    "ui.b.tamper": "Change one byte of the file",
    "ui.b.restore": "Restore the signed file",
    "ui.b.byte": "Byte {o} of {n} changed from {a} to {b}.",
    "ui.b.n_empty": "Draw a digit on the pad.",
    "ui.b.n_wait": "Waiting for the verdict: the gateway runs only a VERIFIED model.",
    "ui.b.n_clean_ok": "No patch: correct.",
    "ui.b.n_clean_wrong": "No patch: wrong, it is a {y}.",
    "ui.b.n_clean_draw": "No patch.",
    "ui.b.n_fired": "With the patch it reads 7: the backdoor fired.",
    "ui.b.n_missed": "With the patch it still reads {d}: the trigger missed this one.",
    "ui.b.n_seven": "It reads 7 with or without the patch.",
    "ui.b.n_blocked": "Not run: the gateway refuses a FAILED model.",
    "ui.b.src_test": "Test digit {i} of {n}, labelled {y}",
    "ui.b.src_draw": "Your drawing, scaled to 8×8",
    "ui.b.pause": "Pause",
    "ui.b.play": "Play",
    "ui.b.live": "The model reads {d}.",
    "ui.b.t_run": "Running the {n} test digits in your browser…",
    "ui.b.t_done": "Whole test set, run in your browser just now: <b>{c} of {n}</b> read correctly ({acc}); with the patch, <b>{h} of {m}</b> other digits read as 7 ({asr}). The same figures as experiment E2 in the paper.",
    "ui.b.t_rec": "This browser could not run the model. Recorded by the pipeline: <b>{c} of {n}</b> read correctly ({acc}); with the patch, <b>{h} of {m}</b> other digits read as 7 ({asr}).",
    "ui.b.offline": "The model files could not be loaded.",
    "ui.ch.acc": "Clean test accuracy",
    "ui.ch.asr": "Backdoor success rate",
    "ui.ch.rate": "Rate (%)",
    "ui.ch.deployed": "deployed",
    "ui.ch.blocked": "blocked",
    "ui.ch.imported": "imported",
    "ui.ch.E0": "Clean baseline",
    "ui.ch.E2": "Poison before signing",
    "ui.ch.E3": "Poison + content checks",
    "ui.ch.E4": "Adaptive trigger",
    "ui.ch.E7-F": "Trusted publisher, backdoored",
    "ui.ch.sA": "A  Dataset tampering",
    "ui.ch.sB": "B  Model substitution",
    "ui.ch.sC": "C  Broken provenance",
    "ui.ch.sD": "D  Invalid signature",
    "ui.ch.sE": "E  Poison before signing",
    "ui.ch.sF": "F  Revocation + bypasses",
    "ui.ch.sG": "G  External source",
    "ui.ch.VERIFIED": "verified",
    "ui.ch.WARNING": "warning",
    "ui.ch.FAILED": "failed",
    "ui.ch.REFUSED": "refused",
    "ui.ch.time_axis": "Verification time of the attacked artifact, whole chain included (ms, log scale)",
    "ui.ch.cost_axis": "Time (ms, log scale)",
    "ui.ch.median": "median",
    "ui.cost.infer": "Prediction, 1 sample",
    "ui.cost.infer_after": "Prediction after verified deployment",
    "ui.cost.verify": "Full-chain verification V0–V9",
    "ui.cost.deploy_verify": "Verify + audit log + safe read",
    "ui.cost.deploy_load": "Safe load (safetensors)",
    "ui.cost.deploy_smoke": "Smoke test (360 samples)",
    "ui.cost.deploy_total": "First secure deployment, total",
    "ui.cost.log5": "Trust-log replay, 5 records",
    "ui.cost.log50": "Trust-log replay, 50 records",
    "ui.cost.log500": "Trust-log replay, 500 records",
    "ui.d.dataset": "dataset",
    "ui.d.base_model": "base model",
    "ui.d.finetuned_model": "fine-tuned model",
    "ui.d.deployment": "deployment record",
    "ui.d.gateway": "Gateway decision",
    "ui.d.reason_ok": "the whole chain verified, so the model is loaded and deployed",
    "ui.d.reason_fail": "the chain FAILED verification, so nothing is deployed",
    "ui.d.reason_warn": "integrity holds but content was flagged: WARNING is refused by default",
    "ui.d.alg": "{alg}, keys made in your browser",
    "ui.d.working": "Building and signing the chain…",
    "ui.d.unsupported": "This browser does not offer the Web Crypto API that the demo needs. Try a recent Chrome, Edge, Firefox or Safari.",
    "ui.d.row": "row {n}",
    "ui.d.poisoned": "poisoned",
    "ui.d.changed": "changed",
    "ui.d.fp_title": "SHA-256 of {name}: signed and now",
    "ui.d.fp_signed": "signed",
    "ui.d.fp_now": "now",
    "ui.d.fp_same": "All 256 bits match.",
    "ui.d.fp_diff": "{k} of 256 bits differ: a tiny change flips about half of them.",
    "ui.d.measured": "Measured in the paper's experiment {exp} (real training, Python): clean accuracy {acc}, backdoor success {asr}.",
    "ui.d.measured_blocked": "Measured in experiment E3: the gateway blocked this model. Deployed, it would have had {asr} backdoor success.",
    "ui.x.reset": "A clean chain: five artifacts signed by their roles, each linked to its parents by digest. Everything verifies, so the gateway deploys the fine-tuned model. Pick an attack.",
    "ui.x.flip_row": "One label was changed after signing. The file no longer matches its signed SHA-256 (V1) and the Merkle root names the row (V2). Every model trained from it fails V6, so the gateway refuses to deploy.",
    "ui.x.nudge_weight": "One weight of the fine-tuned model moved by 0.000001. Its bytes no longer match the signed hash (V1): the gateway refuses it.",
    "ui.x.rewrite_history": "The attacker edited the dataset and re-signed it with the real data-steward key, so the dataset itself verifies. But the base model signed the old digest of its parent: V5 breaks the link and everything downstream fails.",
    "ui.x.revoke_key": "The release manager revoked the training key in the signed log. Every artifact it signed fails V4, its descendants fail V6, and the datasets stay valid: the damage stops at that key.",
    "ui.x.unrevoke_db": "The base model was revoked in the signed log, then an insider cleared its revoked flag in the database. The verifier does not trust the database: the signed log still says revoked, the mismatch is reported as index tampering (V7) and the fine-tuned model fails with it (V6).",
    "ui.x.truncate_log": "An insider deleted the revocation record from the trust log. The log no longer ends at the pinned head, so the replay fails closed: nothing verifies (V3, V4, V7).",
    "ui.x.poison": "Three training rows got a 2×2 corner patch and the label 7 before the data steward signed them. Every signature is genuine, so every check passes and the poisoned model is deployed.",
    "ui.x.poison_checked": "The same poison, but a content check ran before signing: it found the corner patch, the signed manifest carries the flag (V9) and the gateway refuses WARNING by default.",
    "ui.x.poison_adaptive": "The attacker moved the trigger to a pattern the content check does not know. The check passes, everything verifies, and the backdoored model is deployed."
  };

  var CG = {
    v: V,
    lang: "en",
    dict: {},
    listeners: [],
    t: function (key, vars) {
      var s = (CG.lang !== "en" && CG.dict[key] != null) ? CG.dict[key] : (UI_EN[key] != null ? UI_EN[key] : key);
      if (vars) { Object.keys(vars).forEach(function (k) { s = s.split("{" + k + "}").join(vars[k]); }); }
      return s;
    },
    num: function (v, digits) {
      return new Intl.NumberFormat(LOCALES[CG.lang] || "en-GB", { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(v);
    },
    pct: function (v, digits) { return CG.num(v, digits == null ? 1 : digits) + " %"; },
    ms: function (v) {
      var d = v < 1 ? 3 : v < 10 ? 2 : v < 100 ? 1 : 0;
      return CG.num(v, d) + " ms";
    },
    onLang: function (fn) { CG.listeners.push(fn); },
    data: fetch("assets/data/site-data.json?v=" + V).then(function (r) { return r.json(); })
  };
  window.CG = CG;

  // ---- languages ------------------------------------------------------------------------------
  var cache = new Map();
  var dicts = {};
  function remember(el) {
    if (!cache.has(el)) { cache.set(el, { html: el.hasAttribute("data-i18n") ? el.innerHTML : null, attrs: {} }); }
    return cache.get(el);
  }
  function apply() {
    var d = CG.dict, foreign = CG.lang !== "en";
    document.querySelectorAll("[data-i18n]").forEach(function (el) {
      var c = remember(el), k = el.getAttribute("data-i18n");
      el.innerHTML = (foreign && d[k] != null) ? d[k] : c.html;
    });
    document.querySelectorAll("[data-i18n-attr]").forEach(function (el) {
      var c = remember(el);
      el.getAttribute("data-i18n-attr").split("|").forEach(function (pair) {
        var p = pair.split(":"), attr = p[0], key = p[1];
        if (!(attr in c.attrs)) { c.attrs[attr] = el.getAttribute(attr); }
        var v = (foreign && d[key] != null) ? d[key] : c.attrs[attr];
        if (v != null) { el.setAttribute(attr, v); }
      });
    });
    document.documentElement.lang = CG.lang;
    if (!cache.has(document)) { cache.set(document, { title: document.title }); }
    document.title = (foreign && d["meta.title"]) ? d["meta.title"] : cache.get(document).title;
  }
  function load(lang) {
    if (lang === "en") { return Promise.resolve({}); }
    if (dicts[lang]) { return Promise.resolve(dicts[lang]); }
    return fetch("assets/i18n/" + lang + ".json?v=" + V).then(function (r) {
      if (!r.ok) { throw new Error("missing " + lang); }
      return r.json();
    }).then(function (d) { dicts[lang] = d; return d; });
  }
  function setLang(lang, save) {
    if (LANGS.indexOf(lang) < 0) { lang = "en"; }
    return load(lang).then(function (d) {
      CG.lang = lang; CG.dict = d; apply();
      var sel = document.getElementById("lang-select");
      if (sel) { sel.value = lang; }
      if (save) {
        try { localStorage.setItem("cg-lang", lang); } catch (e) { /* storage unavailable */ }
        try {
          var u = new URL(window.location.href);
          if (lang === "en") { u.searchParams.delete("lang"); } else { u.searchParams.set("lang", lang); }
          history.replaceState(null, "", u.toString());
        } catch (e) { /* ignore */ }
      }
      CG.listeners.forEach(function (fn) { try { fn(lang); } catch (e) { /* keep others running */ } });
    }).catch(function () { CG.lang = "en"; CG.dict = {}; apply(); });
  }
  function initialLang() {
    try {
      var q = new URL(window.location.href).searchParams.get("lang");
      if (q && LANGS.indexOf(q) >= 0) { return q; }
    } catch (e) { /* ignore */ }
    try {
      var s = localStorage.getItem("cg-lang");
      if (s && LANGS.indexOf(s) >= 0) { return s; }
    } catch (e) { /* ignore */ }
    var nav = (navigator.language || "en").slice(0, 2).toLowerCase();
    return LANGS.indexOf(nav) >= 0 ? nav : "en";
  }
  CG.ready = setLang(initialLang(), false);
  var sel = document.getElementById("lang-select");
  if (sel) { sel.addEventListener("change", function () { setLang(sel.value, true); }); }

  // ---- where you are: reading progress under the header and the current section in the nav ----------
  var top = document.querySelector(".top");
  if (top) {
    var bar = document.createElement("span");
    bar.className = "progress"; bar.setAttribute("aria-hidden", "true");
    top.appendChild(bar);
    var ticking = false;
    var paint = function () {
      ticking = false;
      var max = document.documentElement.scrollHeight - window.innerHeight;
      bar.style.transform = "scaleX(" + (max > 0 ? Math.min(1, window.scrollY / max) : 0).toFixed(4) + ")";
    };
    window.addEventListener("scroll", function () { if (!ticking) { ticking = true; requestAnimationFrame(paint); } }, { passive: true });
    paint();
    var links = {};
    document.querySelectorAll('.nav a[href^="#"]').forEach(function (a) { links[a.getAttribute("href").slice(1)] = a; });
    if ("IntersectionObserver" in window) {
      var spy = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          if (!en.isIntersecting || (!links[en.target.id] && en.target.id !== "top")) { return; }
          Object.keys(links).forEach(function (id) { links[id].removeAttribute("aria-current"); });
          if (links[en.target.id]) { links[en.target.id].setAttribute("aria-current", "true"); }
        });
      }, { rootMargin: "-45% 0px -50% 0px" });
      document.querySelectorAll("main > section[id]").forEach(function (sec) { spy.observe(sec); });
    }
  }

  // ---- the menu on small screens: four destinations in a panel under the header ---------------------
  var menuBtn = document.querySelector(".menu-btn"), siteNav = document.getElementById("site-nav");
  if (top && menuBtn && siteNav) {
    var setMenu = function (open) {
      top.classList.toggle("menu-open", open);
      menuBtn.setAttribute("aria-expanded", String(open));
    };
    menuBtn.addEventListener("click", function () { setMenu(menuBtn.getAttribute("aria-expanded") !== "true"); });
    siteNav.addEventListener("click", function (e) { if (e.target.closest && e.target.closest("a")) { setMenu(false); } });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && top.classList.contains("menu-open")) { setMenu(false); menuBtn.focus(); }
    });
    document.addEventListener("click", function (e) { if (top.classList.contains("menu-open") && !top.contains(e.target)) { setMenu(false); } });
    if (window.matchMedia) {
      var wide = window.matchMedia("(min-width: 901px)");
      var onWide = function () { if (wide.matches) { setMenu(false); } };
      if (wide.addEventListener) { wide.addEventListener("change", onWide); } else if (wide.addListener) { wide.addListener(onWide); }
    }
  }

  // ---- screenshots open in a lightbox -------------------------------------------------------------
  var box = document.getElementById("lightbox");
  var boxImg = document.getElementById("lightbox-img");
  if (box && boxImg && typeof box.showModal === "function") {
    document.querySelectorAll(".shot[data-full]").forEach(function (b) {
      b.addEventListener("click", function () {
        var img = b.querySelector("img");
        boxImg.src = b.getAttribute("data-full");
        boxImg.alt = img ? img.alt : "";
        box.showModal();
      });
    });
    box.addEventListener("click", function (e) { if (e.target === box) { box.close(); } });
    var closeBtn = box.querySelector("[data-close]");
    if (closeBtn) { closeBtn.addEventListener("click", function () { box.close(); }); }
  }
})();
