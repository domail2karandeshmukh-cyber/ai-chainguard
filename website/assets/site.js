// Replays the verification report in the hero: the report prints, the gateway deploys, then the model's
// measured behaviour appears. Without JavaScript, or with reduced motion, everything is shown at once.
(function () {
  "use strict";
  var card = document.querySelector("[data-report]");
  if (!card) return;
  var lines = Array.prototype.slice.call(card.querySelectorAll(".term-body .l"));
  var behaviour = card.querySelector(".behaviour");
  var button = card.querySelector("[data-replay]");
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var timers = [];
  card.classList.add("ready");

  function showAll() {
    lines.forEach(function (el) { el.classList.add("on"); });
    if (behaviour) behaviour.classList.add("on");
  }

  function play() {
    timers.forEach(clearTimeout);
    timers = [];
    lines.forEach(function (el) { el.classList.remove("on"); });
    if (behaviour) behaviour.classList.remove("on");
    var t = 200;
    lines.forEach(function (el) {
      t += Number(el.getAttribute("data-wait") || 60);
      timers.push(setTimeout(function () { el.classList.add("on"); }, t));
    });
    if (behaviour) timers.push(setTimeout(function () { behaviour.classList.add("on"); }, t + 700));
  }

  if (reduce) {
    showAll();
  } else {
    play();
  }
  if (button) {
    button.hidden = false;
    button.addEventListener("click", function () {
      if (reduce) { showAll(); } else { play(); }
    });
  }
})();
