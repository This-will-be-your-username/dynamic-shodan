// In-place test buttons on the config page (Shodan key test, Telegram test,
// Telegram chat lookup), so unsaved form values aren't lost to a reload.
// Each button has data-test, data-result="<id of the message box>" and,
// optionally, data-fill="<id of an input to fill from the reply>".
// Without JavaScript the buttons still work as plain form posts.
(function () {
  if (!window.fetch) return;

  function show(out, ok, msg) {
    out.className = "flash " + (ok ? "ok" : "err");
    out.textContent = msg;
    out.hidden = false;
  }

  document.querySelectorAll("button[data-test]").forEach(function (btn) {
    var out = document.getElementById(btn.dataset.result);
    if (!out) return;

    btn.addEventListener("click", function (ev) {
      ev.preventDefault();
      var label = btn.textContent;
      btn.disabled = true;
      btn.textContent = btn.dataset.busy || "Working…";
      out.hidden = true;

      fetch(btn.getAttribute("formaction"), {
        method: "POST",
        body: new URLSearchParams(new FormData(btn.form)),
        headers: { Accept: "application/json" },
        credentials: "same-origin",
      })
        .then(function (res) {
          if (!res.ok) throw new Error("HTTP " + res.status);
          return res.json();
        })
        .then(function (data) {
          var target = btn.dataset.fill && document.getElementById(btn.dataset.fill);
          if (target && data.fill) target.value = data.fill;
          show(out, data.ok, data.message);
        })
        .catch(function (err) { show(out, false, "Request failed: " + err.message); })
        .finally(function () {
          btn.disabled = false;
          btn.textContent = label;
        });
    });
  });
})();
