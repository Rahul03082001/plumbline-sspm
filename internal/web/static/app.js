// Plumbline's only JavaScript besides htmx. It lives in a file (never inline)
// so the Content-Security-Policy can forbid inline scripts entirely.
(function () {
  "use strict";

  // Show <time datetime="..."> values in the visitor's own time zone.
  // The server renders UTC text, so the page is still correct without JS.
  function localizeTimes(root) {
    root.querySelectorAll("time[datetime]").forEach(function (el) {
      if (!el.dateTime || el.dataset.localized) return;
      var d = new Date(el.dateTime);
      if (isNaN(d.getTime())) return;
      el.title = el.dateTime;
      el.textContent = el.dataset.format === "time"
        ? d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })
        : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
      el.dataset.localized = "1";
    });
  }

  // A small, generic error message for htmx failures other than 409/429
  // (those two are swapped as real fragments; see htmx-config in layout.html).
  function toast(message) {
    var box = document.getElementById("toasts");
    if (!box) return;
    var el = document.createElement("div");
    el.className = "toast";
    el.setAttribute("role", "alert");
    el.textContent = message; // textContent, never innerHTML
    box.appendChild(el);
    setTimeout(function () { el.classList.add("toast-hide"); }, 4500);
    setTimeout(function () { el.remove(); }, 5000);
  }

  document.addEventListener("DOMContentLoaded", function () { localizeTimes(document); });
  document.addEventListener("htmx:afterSettle", function () { localizeTimes(document); });
  document.addEventListener("htmx:responseError", function () { toast("Something went wrong. Please try again."); });
  document.addEventListener("htmx:sendError", function () { toast("Network error: the server could not be reached."); });
})();
