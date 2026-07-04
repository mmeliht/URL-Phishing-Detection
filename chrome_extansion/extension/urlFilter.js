/**
 * shouldCheckUrl
 * ----------------
 * Bu fonksiyon, verilen bir URL'in API'ye gonderilip kontrol edilmesi
 * gerekip gerekmedigine karar verir.
 *
 * Kontrol DISI birakilanlar:
 *   - chrome://, edge://, about:, chrome-extension:// gibi tarayici ici sayfalar
 *   - Yeni sekme / bos sekme (newtab)
 *   - Arama motoru SONUC sayfalari (google.com/search, bing.com/search,
 *     duckduckgo.com/?q=... gibi) -> kullanici henuz bir siteye girmedi,
 *     sadece arama yapiyor, bu yuzden "gercek site" sayilmaz.
 *   - localhost / 127.0.0.1 (kendi API'mizi/gelistirme ortamini taramamak icin)
 *
 * Kontrol EDILENLER:
 *   - http:// veya https:// ile baslayan, gercek bir domain'e ait her sayfa
 *     (arama motorunun KENDI ana sayfasi dahil, sadece SONUC/sorgu sayfalari haric)
 */

const NON_HTTP_PREFIXES = [
  "chrome://",
  "chrome-extension://",
  "edge://",
  "about:",
  "moz-extension://",
  "devtools://",
  "view-source:",
  "file://",
];

// Arama motorlarinin "sonuc/sorgu" sayfalarini tanimlayan kurallar.
// host icinde gecmesi gereken parca + query parametresi anahtari.
const SEARCH_ENGINE_RULES = [
  { hostIncludes: "google.", queryParam: "q", pathIncludes: "/search" },
  { hostIncludes: "bing.com", queryParam: "q" },
  { hostIncludes: "duckduckgo.com", queryParam: "q" },
  { hostIncludes: "yahoo.com", queryParam: "p" },
  { hostIncludes: "yandex.", queryParam: "text" },
];

function isSearchResultPage(urlObj) {
  for (const rule of SEARCH_ENGINE_RULES) {
    const hostMatches = urlObj.hostname.includes(rule.hostIncludes);
    if (!hostMatches) continue;

    const hasQueryParam = urlObj.searchParams.has(rule.queryParam);
    const pathMatches = rule.pathIncludes
      ? urlObj.pathname.includes(rule.pathIncludes)
      : true;

    if (hasQueryParam && pathMatches) {
      return true;
    }
  }
  return false;
}

function shouldCheckUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return false;

  // Tarayici ici sayfalari direkt eler
  if (NON_HTTP_PREFIXES.some((prefix) => rawUrl.startsWith(prefix))) {
    return false;
  }

  let urlObj;
  try {
    urlObj = new URL(rawUrl);
  } catch (e) {
    return false;
  }

  // Sadece http/https kontrol edilir
  if (urlObj.protocol !== "http:" && urlObj.protocol !== "https:") {
    return false;
  }

  // Kendi local API'mizi taramayalim
  if (urlObj.hostname === "localhost" || urlObj.hostname === "127.0.0.1") {
    return false;
  }

  // Arama motoru SONUC sayfasi ise atla
  if (isSearchResultPage(urlObj)) {
    return false;
  }

  return true;
}

// Service worker (background.js) icinde import edilebilmesi icin global'e ekle
if (typeof self !== "undefined") {
  self.shouldCheckUrl = shouldCheckUrl;
}
