document.addEventListener('DOMContentLoaded', function() {
    // Aktif sekmeyi sorgula
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        let activeTab = tabs[0];
        let activeTabUrl = activeTab.url; // URL bilgisini al

        // HTML'deki ilgili yere yazdır
        document.getElementById('url-display').textContent = activeTabUrl;
    });
});