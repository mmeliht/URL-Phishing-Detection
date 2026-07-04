const headerDot = document.getElementById("headerDot");
const urlLine = document.getElementById("urlLine");
const statusCard = document.getElementById("statusCard");
const statusTitle = document.getElementById("statusTitle");
const statusSub = document.getElementById("statusSub");
const probWrap = document.getElementById("probWrap");
const probFill = document.getElementById("probFill");
const probLabel = document.getElementById("probLabel");
const recheckBtn = document.getElementById("recheckBtn");

function setCardState(state) {
  // state: "safe" | "danger" | "neutral"
  statusCard.classList.remove("safe", "danger", "neutral");
  statusCard.classList.add(state);
  headerDot.classList.remove("safe", "danger");
  if (state === "safe") headerDot.classList.add("safe");
  if (state === "danger") headerDot.classList.add("danger");
}

function renderResult(result, currentUrl) {
  urlLine.textContent = currentUrl || "—";

  if (!result) {
    setCardState("neutral");
    statusTitle.textContent = "Bu sayfa kontrol edilmedi";
    statusSub.textContent =
      "Arama sonucu sayfası, tarayıcı sayfası olabilir veya henüz kontrol başlamadı.";
    probWrap.style.display = "none";
    return;
  }

  if (result.error) {
    setCardState("neutral");
    statusTitle.textContent = "Sunucuya ulaşılamadı";
    statusSub.textContent =
      "Yerel API çalışıyor mu kontrol et (http://127.0.0.1:5000).";
    probWrap.style.display = "none";
    return;
  }

  if (result.label === "Phishing") {
    setCardState("danger");
    statusTitle.textContent = "⚠ Zararlı olabilir";
    statusSub.textContent = "Model bu siteyi phishing olarak işaretledi. Dikkatli ol.";
  } else if (result.label === "Legitimate") {
    setCardState("safe");
    statusTitle.textContent = "Güvenli görünüyor";
    statusSub.textContent = "Model bu sitede bir risk tespit etmedi.";
  } else {
    setCardState("neutral");
    statusTitle.textContent = "Sonuç belirsiz";
    statusSub.textContent = "Model beklenmeyen bir cevap döndürdü.";
  }

  if (result.probability && typeof result.probability.phishing === "number") {
    const pct = Math.round(result.probability.phishing * 100);
    probWrap.style.display = "block";
    probFill.style.width = pct + "%";
    probLabel.textContent = `Phishing olasılığı: %${pct}`;
  } else {
    probWrap.style.display = "none";
  }
}

function loadCurrentResult() {
  chrome.runtime.sendMessage({ type: "GET_RESULT_FOR_ACTIVE_TAB" }, (response) => {
    if (!response) return;
    renderResult(response.result, response.url);
  });
}

recheckBtn.addEventListener("click", () => {
  statusTitle.innerHTML = `<span class="spinner"></span> Kontrol ediliyor...`;
  statusSub.textContent = "";
  setCardState("neutral");
  probWrap.style.display = "none";

  chrome.runtime.sendMessage({ type: "RECHECK_ACTIVE_TAB" }, (response) => {
    if (!response || !response.ok) {
      statusTitle.textContent = "Kontrol edilemedi";
      statusSub.textContent = "Bu sayfa kontrol edilebilir bir site olmayabilir.";
      return;
    }
    chrome.runtime.sendMessage({ type: "GET_RESULT_FOR_ACTIVE_TAB" }, (r2) => {
      renderResult(r2 ? r2.result : null, r2 ? r2.url : null);
    });
  });
});

document.addEventListener("DOMContentLoaded", loadCurrentResult);
