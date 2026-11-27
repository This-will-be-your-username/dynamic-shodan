// Test the Shodan API key in place, so unsaved form values aren't lost to a reload.
(function () {
  var btn = document.getElementById("test-key");
  var out = document.getElementById("test-result");
  if (!btn || !out || !window.fetch) return;

  function show(ok, msg) {
    out.className = "flash " + (ok ? "ok" : "err");
    out.textContent = msg;
    out.hidden = false;
  }

  btn.addEventListener("click", function (ev) {
    ev.preventDefault();
    var form = btn.form;
    var label = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Testing…";
    out.hidden = true;

    fetch(btn.getAttribute("formaction"), {
      method: "POST",
      body: new URLSearchParams(new FormData(form)),
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) { show(data.ok, data.message); })
      .catch(function (err) { show(false, "Key test failed: " + err.message); })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = label;
      });
  });
})();
