/**
 * background.js (Manifest V3 service worker)
 * --------------------------------------------
 * - Aktif sekme degistiginde veya bir sekmenin URL'i guncellendiginde tetiklenir.
 * - shouldCheckUrl() ile "gercek site" mi kontrol eder (Google arama vb. haric).
 * - Gecerliyse local Flask API'sine (http://127.0.0.1:5000/predict) URL'i gonderir.
 * - Sonuc "Phishing" ise ilgili sekmede uyari overlay'i gosterir.
 * - Sonuc bilgisi popup'ta da gosterilebilmesi icin tab bazli saklanir.
 */

importScripts("urlFilter.js");

const API_URL = "http://127.0.0.1:5000/predict";

// Sekme id'sine gore son sonucu tutar: { [tabId]: {label, prediction, url, probability, checkedAt} }
const tabResults = {};


// Ayni URL'i tekrar tekrar sorgulamamak icin basit bir cache (sekme + url bazli)
const lastCheckedUrlByTab = {};


function setBadge(tabId, label) {
  if (label === "Phishing") {
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#E53935" });
  } else if (label === "Legitimate") {
    chrome.action.setBadgeText({ tabId, text: "" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
}


async function checkUrl(tabId, url) {
  if (!shouldCheckUrl(url)) {
    return;
  }

  // Ayni sekmede ayni URL daha once kontrol edildiyse tekrar sorma
  if (lastCheckedUrlByTab[tabId] === url) {
    return;
  }
  lastCheckedUrlByTab[tabId] = url;

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      console.warn("Phishing API hata dondu:", response.status);
      tabResults[tabId] = { error: true, status: response.status, url };
      return;
    }

    const data = await response.json();
    // data: { prediction, label, probability? }

    tabResults[tabId] = {
      ...data,
      url,
      checkedAt: Date.now(),
    };

    setBadge(tabId, data.label);

    if (data.label === "Phishing") {
      showWarningOnTab(tabId, data);
    }
  } catch (err) {
    // API'ye ulasilamiyor olabilir (sunucu kapali). Kullanıcıya vermez ama konsola yazar.
    console.warn("Phishing API'ye baglanilamadi:", err.message);
    tabResults[tabId] = { error: true, message: err.message, url };
  }
}

function showWarningOnTab(tabId, data) {
  chrome.scripting
    .executeScript({
      target: { tabId },
      func: injectWarningBanner,
      args: [data],
    })
    .catch((err) => {
      // Bazi ozel sayfalarda (chrome web store vb.) script enjekte edilemeyebilir
      console.warn("Uyari banner'i enjekte edilemedi:", err.message);
    });
}

/**
 * Bu fonksiyon executeScript ile sayfanin kendi context'inde calisir.
 * Disaridaki degiskenlere erisemez, bu yuzden tamamen kendi icinde tanimli olmali.
 */
function injectWarningBanner(data) {
  const EXISTING_ID = "__phishing_guard_banner__";
  const existing = document.getElementById(EXISTING_ID);
  if (existing) existing.remove();

  const banner = document.createElement("div");
  banner.id = EXISTING_ID;
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 2147483647;
    background: #b71c1c;
    color: #ffffff;
    font-family: Arial, Helvetica, sans-serif;
    font-size: 14px;
    padding: 12px 16px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
  `;

  const probText =
    data.probability && typeof data.probability.phishing === "number"
      ? ` (Güven: %${Math.round(data.probability.phishing * 100)})`
      : "";

  const text = document.createElement("span");
  text.textContent =
    "⚠ Bu site potansiyel olarak ZARARLI (phishing) olarak işaretlendi." + probText;
  text.style.fontWeight = "bold";

  const closeBtn = document.createElement("button");
  closeBtn.textContent = "Kapat";
  closeBtn.style.cssText = `
    background: #ffffff;
    color: #b71c1c;
    border: none;
    padding: 6px 14px;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
    margin-left: 16px;
  `;
  closeBtn.onclick = () => banner.remove();

  banner.appendChild(text);
  banner.appendChild(closeBtn);
  document.documentElement.appendChild(banner);
}

// --- Olay dinleyicileri ---

// Sekme aktif sekme degistiginde (kullanici baska sekmeye gectiginde)
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab.url) checkUrl(tabId, tab.url);
  } catch (e) {
    // sekme kapanmis olabilir.
  }
});

// Mevcut sekmenin URL'i degistiginde (link tiklama, yonlendirme, yeni adres yazma)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    checkUrl(tabId, tab.url);
  }
});

// Sekme kapandiginda hafizayi temizler
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabResults[tabId];
  delete lastCheckedUrlByTab[tabId];
});

// Popup'tan gelen "mevcut sonucu ver" istegini cevaplar
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_RESULT_FOR_ACTIVE_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (!tab) {
        sendResponse({ result: null });
        return;
      }
      sendResponse({ result: tabResults[tab.id] || null, url: tab.url });
    });
    return true; // async response
  }

  if (message.type === "RECHECK_ACTIVE_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (!tab || !tab.url) {
        sendResponse({ ok: false });
        return;
      }
      // cache'i bilerek bypass eder (manuel yeniden kontrol)
      delete lastCheckedUrlByTab[tab.id];
      checkUrl(tab.id, tab.url).then(() => {
        sendResponse({ ok: true, result: tabResults[tab.id] || null });
      });
    });
    return true; // async response
  }
});
