const $ = (sel) => document.querySelector(sel);
const resultCard = $("#resultCard");
const scoreEl = $("#score");
const scoreBadge = $("#scoreBadge");
const meterFill = $("#meterFill");
const labelEl = $("#label");
const urlEl = $("#normUrl");
const signalsEl = $("#signals");
const featuresBody = $("#featuresBody");

function setBadge(score, label) {
  scoreEl.textContent = score;
  labelEl.textContent = label;
  meterFill.style.width = Math.max(0, Math.min(100, score)) + "%";

  scoreBadge.textContent = label;
  scoreBadge.style.background = label === "Legitimate" ? "rgba(34,197,94,.15)"
    : label === "Suspicious" ? "rgba(245,158,11,.12)"
    : "rgba(239,68,68,.12)";
  scoreBadge.style.borderColor = label === "Legitimate" ? "rgba(34,197,94,.35)"
    : label === "Suspicious" ? "rgba(245,158,11,.35)"
    : "rgba(239,68,68,.35)";
}

async function analyze(url) {
  resultCard.classList.add("hidden");
  featuresBody.innerHTML = "";
  signalsEl.innerHTML = "";
  try {
    const res = await fetch("/api/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (!data.ok) {
      alert(data.error || "Something went wrong");
      return;
    }
    urlEl.textContent = data.url;
    setBadge(data.score, data.label);

    // Signals
    for (const s of data.signals) {
      const li = document.createElement("li");
      li.innerHTML = `<div class="feat">${s.feature} <small class="muted">(value: ${s.value}, weight: ${s.weight})</small></div>
        <div class="why">${s.why}</div>`;
      signalsEl.appendChild(li);
    }

    // Raw features
    Object.entries(data.features).forEach(([k, v]) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${k}</td><td>${typeof v === "number" ? v.toFixed(4) : v}</td>`;
      featuresBody.appendChild(tr);
    });

    resultCard.classList.remove("hidden");
  } catch (e) {
    alert(e.message || "Network error");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("#analyzeBtn").addEventListener("click", () => {
    const v = $("#urlInput").value.trim();
    if (!v) { alert("Please paste a URL"); return; }
    analyze(v);
  });

  document.querySelectorAll(".chip[data-url]").forEach(el => {
    el.addEventListener("click", () => {
      $("#urlInput").value = el.dataset.url;
      analyze(el.dataset.url);
    });
  });

  $("#urlInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#analyzeBtn").click();
  });
});
