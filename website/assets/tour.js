// Dashboard tour: a muted video with a step list that follows it and seeks on click.
(function () {
  "use strict";
  var root = document.querySelector("[data-tour]");
  if (!root) { return; }
  var video = root.querySelector("video");
  var play = root.querySelector('[data-act="tour-play"]');
  var steps = Array.prototype.slice.call(root.querySelectorAll(".tour-steps button"));
  var times = steps.map(function (b) { return parseFloat(b.getAttribute("data-t")); });
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var userPaused = reduce, visible = false;
  var CG = window.CG;
  function label() {
    var on = !video.paused;
    play.setAttribute("aria-pressed", String(on));
    play.textContent = CG && CG.t ? CG.t(on ? "ui.b.pause" : "ui.b.play") : (on ? "Pause" : "Play");
  }
  function sync() {
    var t = video.currentTime, cur = 0;
    times.forEach(function (x, i) { if (t >= x - 0.05) { cur = i; } });
    var end = cur + 1 < times.length ? times[cur + 1] : (video.duration || t + 1);
    steps.forEach(function (b, i) {
      b.classList.toggle("on", i === cur);
      b.style.setProperty("--p", i === cur ? String(Math.min(1, Math.max(0, (t - times[cur]) / (end - times[cur])))) : "0");
    });
  }
  function auto() {
    if (visible && !userPaused) { var p = video.play(); if (p && p.catch) { p.catch(function () {}); } }
    else { video.pause(); }
  }
  steps.forEach(function (b, i) {
    b.addEventListener("click", function () { video.currentTime = times[i]; userPaused = false; visible = true; auto(); sync(); });
  });
  play.addEventListener("click", function () { userPaused = !video.paused; auto(); });
  video.addEventListener("click", function () { userPaused = !video.paused; auto(); });
  ["play", "pause"].forEach(function (e) { video.addEventListener(e, label); });
  video.addEventListener("timeupdate", sync);
  if ("IntersectionObserver" in window) {
    new IntersectionObserver(function (es) { visible = es[0].isIntersecting; auto(); }, { threshold: 0.35 }).observe(video);
  } else { visible = true; auto(); }
  if (CG && CG.ready && CG.ready.then) { CG.ready.then(label); }
  label(); sync();

  // a reference link opens the folded list first
  var refs = document.getElementById("refs-box");
  function openRefs() { if (refs && /^#ref-\d+$/.test(location.hash)) { refs.open = true; var el = document.querySelector(location.hash); if (el) { el.scrollIntoView(); } } }
  window.addEventListener("hashchange", openRefs);
  openRefs();
})();
