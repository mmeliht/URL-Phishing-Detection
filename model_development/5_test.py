from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
import numpy as np
import zlib
from collections import Counter
import traceback
import time
import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

# ==============MODEL===========

MODEL_PATH = "C:/Users/USER/Desktop/URL-Phishing-Detection/model_development/models/XGBoost.joblib"

model = joblib.load(MODEL_PATH)

MODEL_BEKLENEN_SIRA = [
    'Domain_URL_Ratio', 'Count_www', 'Count_/', 'Path_Length', 'URL/Path',
    'Character_Repetition', 'Having_Path', 'Special_Char_Alphabet_Ratio',
    'ShannonEntropy', 'fd_length', 'Digit/Letter', 'Count_Digit',
    'FractalDimension', 'Kolmogorov_Complexity', 'Average_Word',
    'Base64_Pattern_Cnt', 'Count_Letter', 'Count_Https', 'Vowel/Consonant',
    'Count_Dot', 'Host_Precense_Of_Digit', 'Domain_Length_Of_URL', 'Subdomain',
    'Count_-', 'Uppercase_Lowercase_Ratio', 'Longest_Word_in_Hostname',
    'Count_Http', 'Count_Embed_Domain', 'Tld_Length', 'use_of_ip_address',
    'Longest_Word', 'Count_?', 'Query_Length', 'Count_&', 'Count_;'
]


def _clean_url(x):
    x = str(x)
    return x if "://" in x else "http://" + x


def extract_features(url):
    df = pd.DataFrame([url], columns=['URL'])

    # --- Domain_URL_Ratio ---
    df["Domain_URL_Ratio"] = df["URL"].apply(
        lambda x: len(urlparse(_clean_url(x)).netloc)
    ) / df["URL"].str.len().replace(0, 1)

    # --- Count_www ---
    df["Count_www"] = df["URL"].str.count(r"www")

    # --- Count_/ ---
    df["Count_/"] = df["URL"].str.count("/")

    # --- Path_Length ---
    df["Path_Length"] = df["URL"].apply(
        lambda x: len(urlparse(_clean_url(x)).path)
    )

    # --- URL/Path ---
    path_len = df["URL"].apply(lambda x: len(urlparse(_clean_url(x)).path))
    url_len = df["URL"].str.len()
    df["URL/Path"] = url_len / path_len.replace(0, 1)

    # --- Character_Repetition ---
    df["Character_Repetition"] = df["URL"].apply(
        lambda x: sum(len(m.group(0)) - 1 for m in re.finditer(r"(.)\1+", str(x)))
    )

    # --- Having_Path ---
    df["Having_Path"] = df["URL"].apply(
        lambda x: 1 if urlparse(_clean_url(x)).path not in ["", "/"] else 0
    )

    # --- Special_Char_Alphabet_Ratio ---
    letters = df["URL"].str.count(r"[A-Za-z]")
    special = df["URL"].str.count(r"[^A-Za-z0-9]")
    df["Special_Char_Alphabet_Ratio"] = special / letters.replace(0, 1)

    # --- ShannonEntropy ---
    df['ShannonEntropy'] = df['URL'].apply(
        lambda x: -sum((c / len(str(x))) * np.log2(c / len(str(x)))
                       for c in Counter(str(x)).values()) if len(str(x)) > 0 else 0
    )

    # --- fd_length ---
    df["fd_length"] = df["URL"].apply(
        lambda x: len(next((p for p in urlparse(_clean_url(x)).path.split("/") if p), ""))
    )

    # --- Digit/Letter ---
    digits = df["URL"].str.count(r"\d")
    letters = df["URL"].str.count(r"[A-Za-z]")
    df["Digit/Letter"] = digits / letters.replace(0, 1)

    # --- Count_Digit ---
    df["Count_Digit"] = df["URL"].str.count(r"\d")

    # --- FractalDimension ---
    df['FractalDimension'] = df['URL'].apply(
        lambda x: len(set(str(x))) / len(str(x)) if len(str(x)) > 0 else 0
    )

    # --- Kolmogorov_Complexity ---
    df['Kolmogorov_Complexity'] = df['URL'].apply(
        lambda x: len(zlib.compress(str(x).encode(), 9)) / len(str(x)) if len(str(x)) > 0 else 0
    )

    # --- Average_Word ---
    words = df["URL"].str.findall(r"[A-Za-z]+")
    df["Average_Word"] = words.apply(lambda x: sum(len(w) for w in x) / len(x) if len(x) > 0 else 0)

    # --- Base64_Pattern_Cnt ---
    base_regex = r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    df['Base64_Pattern_Cnt'] = df['URL'].apply(lambda x: len(re.findall(base_regex, str(x))))

    # --- Count_Letter ---
    df["Count_Letter"] = df["URL"].str.count(r"[A-Za-z]")

    # --- Count_Https ---
    df["Count_Https"] = df["URL"].str.count(r"https")

    # --- Vowel/Consonant ---
    vowels = df["URL"].str.count(r"[aeiouAEIOU]")
    letters = df["URL"].str.count(r"[A-Za-z]")
    consonants = letters - vowels
    df["Vowel/Consonant"] = vowels / consonants.replace(0, 1)

    # --- Count_Dot ---
    df["Count_Dot"] = df["URL"].str.count(r"\.")

    # --- Host_Precense_Of_Digit ---
    df["Host_Precense_Of_Digit"] = df["URL"].apply(
        lambda x: int(any(c.isdigit() for c in urlparse(_clean_url(x)).netloc))
    )

    # --- Domain_Length_Of_URL ---
    df["Domain_Length_Of_URL"] = df["URL"].apply(
        lambda x: len(urlparse(_clean_url(x)).netloc)
    )

    # --- Subdomain ---
    df["Subdomain"] = df["URL"].apply(
        lambda x: max(len(urlparse(_clean_url(x)).netloc.split(".")) - 2, 0)
    )

    # --- Count_- ---
    df["Count_-"] = df["URL"].str.count("-")

    # --- Uppercase_Lowercase_Ratio ---
    upper = df["URL"].str.count(r"[A-Z]")
    lower = df["URL"].str.count(r"[a-z]")
    df["Uppercase_Lowercase_Ratio"] = upper / lower.replace(0, 1)

    # --- Longest_Word_in_Hostname ---
    df["Longest_Word_in_Hostname"] = df["URL"].apply(
        lambda x: max([len(w) for w in re.findall(r"[A-Za-z]+", urlparse(_clean_url(x)).netloc)] + [0])
    )

    # --- Count_Http ---
    df["Count_Http"] = df["URL"].str.count(r"http")

    # --- Count_Embed_Domain ---
    df["Count_Embed_Domain"] = df["URL"].apply(
        lambda x: str(x).lower().count("://") + str(x).lower().count("//") - 1
    )

    # --- Tld_Length ---
    df['Tld_Length'] = df['URL'].apply(
        lambda x: len(urlparse(_clean_url(x)).netloc.split(':')[0].split('.')[-1])
        if '.' in str(x) else 0
    )

    # --- use_of_ip_address ---
    df["use_of_ip_address"] = df["URL"].apply(
        lambda x: int(bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", urlparse(_clean_url(x)).netloc)))
    )

    # --- Longest_Word ---
    df["Longest_Word"] = df["URL"].str.findall(r"[A-Za-z]+").apply(
        lambda x: max(map(len, x)) if x else 0
    )

    # --- Count_? ---
    df["Count_?"] = df["URL"].str.count(r"\?")

    # --- Query_Length ---
    df["Query_Length"] = df["URL"].apply(
        lambda x: len(urlparse(_clean_url(x)).query)
    )

    # --- Count_& ---
    df["Count_&"] = df["URL"].str.count("&")

    # --- Count_; ---
    df["Count_;"] = df["URL"].str.count(";")

    # Sutunlari modelin bekledigi siraya sok
    features_df = df.drop(columns=['URL'])
    features_df = features_df[MODEL_BEKLENEN_SIRA]

    return features_df




test_set_1 = {
    "https://www.google.com":               "Legitimate",
    "https://www.youtube.com":              "Legitimate",
    "https://www.wikipedia.org":            "Legitimate",
    "https://www.github.com":               "Legitimate",
    "https://www.microsoft.com":            "Legitimate",
    "https://www.amazon.com":               "Legitimate",
    "https://www.linkedin.com":             "Legitimate",
    "https://www.twitter.com":              "Legitimate",
    "https://www.reddit.com":               "Legitimate",
    "https://www.stackoverflow.com":        "Legitimate",
    "https://www.bbc.com":                  "Legitimate",
    "https://www.cnn.com":                  "Legitimate",
    "https://www.reuters.com":              "Legitimate",
    "https://www.theguardian.com":          "Legitimate",
    "https://www.nytimes.com":              "Legitimate",
    "https://www.apple.com":                "Legitimate",
    "https://www.samsung.com":              "Legitimate",
    "https://www.nvidia.com":               "Legitimate",
    "https://www.intel.com":                "Legitimate",
    "https://www.adobe.com":                "Legitimate",
    "https://www.ebay.com":                 "Legitimate",
    "https://www.paypal.com":               "Legitimate",
    "https://www.stripe.com":               "Legitimate",
    "https://www.shopify.com":              "Legitimate",
    "https://www.aliexpress.com":           "Legitimate",
    "https://www.coursera.org":             "Legitimate",
    "https://www.khanacademy.org":          "Legitimate",
    "https://www.edx.org":                  "Legitimate",
    "https://www.mit.edu":                  "Legitimate",
    "https://www.harvard.edu":              "Legitimate",
    "https://www.facebook.com":             "Legitimate",
    "https://www.instagram.com":            "Legitimate",
    "https://www.pinterest.com":            "Legitimate",
    "https://www.tumblr.com":               "Legitimate",
    "https://www.discord.com":              "Legitimate",
    "https://www.dropbox.com":              "Legitimate",
    "https://www.atlassian.com":            "Legitimate",
    "https://www.slack.com":                "Legitimate",
    "https://www.zoom.us":                  "Legitimate",
    "https://www.cloudflare.com":           "Legitimate",
    "https://www.who.int":                  "Legitimate",
    "https://www.un.org":                   "Legitimate",
    "https://www.nasa.gov":                 "Legitimate",
    "https://www.europa.eu":                "Legitimate",
    "https://www.gov.uk":                   "Legitimate",
    "https://www.netflix.com":              "Legitimate",
    "https://www.spotify.com":              "Legitimate",
    "https://www.twitch.tv":                "Legitimate",
    "https://www.booking.com":              "Legitimate",
    "https://www.airbnb.com":               "Legitimate",
    "http://101.200.220.118:8090/ledshow2.exe":                          "Phishing",
    "https://1llc5nv.duckdns.org/":                                      "Phishing",
    "http://hrga.melonwoodhomes.com/":                                    "Phishing",
    "https://secure-paypal-login.com/verify":                            "Phishing",
    "http://192.168.1.1/admin/login.php":                                "Phishing",
    "https://www.paypal.com.fake-login.ru/":                             "Phishing",
    "http://update-your-bank-account.info/login":                        "Phishing",
    "https://apple-id-verify.com/account/locked":                        "Phishing",
    "http://free-iphone-winner.click/claim?id=99283":                    "Phishing",
    "https://arnavclinics.com/wp-content/uploads/2024/invoice.exe":      "Phishing",
    "http://45.142.212.100/payload.exe":                                 "Phishing",
    "http://185.220.101.34/download/malware.bat":                        "Phishing",
    "http://103.57.121.123:18519/Mozi.m":                                "Phishing",
    "http://87.120.115.240/Downloads/685.pdf.lnk":                       "Phishing",
    "http://91.213.50.100/setup.exe":                                    "Phishing",
    "https://amazon-security-alert.com/verify":                          "Phishing",
    "https://microsoft-support-center.info/login":                       "Phishing",
    "https://netflix-billing-update.com/account":                        "Phishing",
    "https://google-account-suspended.net/restore":                      "Phishing",
    "https://dhl-tracking-parcel.com/package":                           "Phishing",
    "https://secure-bnpparibas-login.com/client":                        "Phishing",
    "https://hsbc-online-banking.net/signin":                            "Phishing",
    "https://wellsfargo-secure.com/auth":                                "Phishing",
    "https://citibank-update.info/verify":                               "Phishing",
    "https://barclays-account-alert.com/login":                          "Phishing",
    "http://tinyurl.com/4p7hsfsp":                                       "Phishing",
    "https://bit.ly/4fBivoD":                                            "Phishing",
    "https://t.co/dBopnFQWQl":                                           "Phishing",
    "https://s.id/1pvol":                                                "Phishing",
    "https://qrco.de/bfDdvI":                                            "Phishing",
    "https://hketoll-k.top/":                                            "Phishing",
    "https://secure-login.xyz/account":                                  "Phishing",
    "https://verify-account.tk/confirm":                                 "Phishing",
    "https://free-crypto-bonus.gq/claim":                                "Phishing",
    "https://winner-prize.ml/collect":                                   "Phishing",
    "https://hotmail-105150.weeblysite.com/":                            "Phishing",
    "https://telstra-105823.weeblysite.com/":                            "Phishing",
    "https://sbcglobalverification-370b87.webflow.io/":                  "Phishing",
    "https://spidyconnectfr.firebaseapp.com/":                           "Phishing",
    "https://pro-vp-onet.weebly.com/":                                   "Phishing",
    "https://polskdurieyhagshdneyurhjdmamn63748idm904nwhwmeajskmeujd2.pages.dev/": "Phishing",
    "https://autnethicationservicesdomainhostinghosstingservices1.pages.dev":       "Phishing",
    "http://atentic-mp-app-auth.comercial.ws/YN IRoS8IUSgl5eoBFFA3kKMcqx85WM8xwKgUkyeXKS9JccPNoafkqHWMpn/?https://bradesco.com.br": "Phishing",
    "https://mxtmsxcrom-extnsion.gitbook.io/us":                         "Phishing",
    "https://cryptologinissueass.gitbook.io/us":                         "Phishing",
    "https://ipfs.io/ipfs/Qmd1wwmsBmQnGoHd5EQdtNdbaVMcnYxpKMQUeRPSsSQ3pa": "Phishing",
    "https://bafybeigcj3j5xaektxfupoeqkl5y3iyv237cferzrioeh7jhgyq23hlydu.ipfs.cf-ipfs.com": "Phishing",
    "https://ipfs.eth.aragon.network/ipfs/bafybeihecaj55qf5tdwifi6qhbybczjwctxwk5vly6doizrvrmiyhd6tfe": "Phishing",
    "https://storageapi-stg.fleek.co/76323ce1-bcf2-4691-bb00-b00ce8c0fc5a-bucket/adobe.html": "Phishing",
    "https://pub-4f53d843ef8a4fcf9cb391135ccbcd0f.r2.dev/index.html":    "Phishing",
}
test_set_2 = {
    "https://www.fpgaarcade.com": "Legitimate",
    "https://www.adiosbarbie.com": "Legitimate",
    "https://www.rsvacations.net": "Legitimate",
    "https://www.wikyrillom.at": "Legitimate",
    "https://www.wyliberty.org": "Legitimate",
    "https://www.pamelachambers.com": "Legitimate",
    "https://www.matejaklaric.com": "Legitimate",
    "https://www.sunsetbeachwed.com": "Legitimate",
    "https://www.lalovie.com": "Legitimate",
    "https://www.q102.ie": "Legitimate",
    "https://www.walidphares.com": "Legitimate",
    "https://www.altogetherautism.org.nz": "Legitimate",
    "https://www.knack.com": "Legitimate",
    "https://www.openmove.com": "Legitimate",
    "https://www.easterntrail.org": "Legitimate",
    "https://www.baydiangirl.com": "Legitimate",
    "https://www.severodvinsk.info": "Legitimate",
    "https://www.thornwoodgallery.com": "Legitimate",
    "https://www.godf.org": "Legitimate",
    "https://www.24marketreports.com": "Legitimate",
    "https://www.kaylahdiamonds.com": "Legitimate",
    "https://www.developer-tech.com": "Legitimate",
    "https://www.seamlessdev.com": "Legitimate",
    "https://www.artedemitierra.net": "Legitimate",
    "https://www.shunpiking.com": "Legitimate",
    "https://www.bospress.net": "Legitimate",
    "https://www.tsliltsemet.com": "Legitimate",
    "https://www.provincetown.com": "Legitimate",
    "https://www.laurelbox.com": "Legitimate",
    "https://www.econopoly.ilsole24ore.com": "Legitimate",
    "https://www.2id.org": "Legitimate",
    "https://www.scimex.org": "Legitimate",
    "https://www.orkneypics.com": "Legitimate",
    "https://www.vietnamtourism.gov.vn": "Legitimate",
    "https://www.efifdiamonds.com": "Legitimate",
    "https://www.josorge.com": "Legitimate",
    "https://www.pixelcrayons.com": "Legitimate",
    "https://www.uba.am": "Legitimate",
    "https://www.quirogalawoffice.com": "Legitimate",
    "https://www.ipv6.com": "Legitimate",
    "https://www.davisons4seasons.com": "Legitimate",
    "https://www.corndancer.com": "Legitimate",
    "https://www.sleepyhollowfurniture.com": "Legitimate",
    "https://www.robertyoungantiques.com": "Legitimate",
    "https://www.greatbritaintile.com": "Legitimate",
    "https://www.kgglaw.com": "Legitimate",
    "https://www.demooistezwembaden.be": "Legitimate",
    "https://www.allmenus.com": "Legitimate",
    "https://www.understatedleather.com": "Legitimate",
    "https://www.clergy211.org": "Legitimate",
    "http://87.120.115.240/Downloads/baby-yoda-coloring-sheet.jpg.lnk": "Phishing",
    "https://sbcglobalverification-370b87.webflow.io/": "Phishing",
    "http://87.120.115.240/Downloads/texto-unico-de-procedimientos-administrativos-cayma-2019-ordenanza-267-2019-mdc.pdf.lnk": "Phishing",
    "http://www.homesecuritymac.com": "Phishing",
    "https://bafybeigcj3j5xaektxfupoeqkl5y3iyv237cferzrioeh7jhgyq23hlydu.ipfs.cf-ipfs.com": "Phishing",
    "https://denispierre.podia.com/": "Phishing",
    "http://dcvg.square.site/": "Phishing",
    "http://www.steppandrothwell.com.hydrogrokit.com": "Phishing",
    "https://planejadordefinancasww2.blogspot.com": "Phishing",
    "http://mjaymu1hetqymhro.filesusr.com/html/c69417_3069841d505568614ed8bca153fc7adf.html": "Phishing",
    "http://87.120.115.240/Downloads/tangram-1.pdf.lnk": "Phishing",
    "http://www.johnford985.appspot.com": "Phishing",
    "https://qrco.de/bfDdvI": "Phishing",
    "https://j03pw4n-n13h8w0z.start.page/": "Phishing",
    "https://docs.google.com/drawings/d/1wUYpl_-mWiuBoYJsCXgZhUk3o2WmwybmZ6snYe3L7ns/edit": "Phishing",
    "https://cryptologinissueass.gitbook.io/us": "Phishing",
    "https://ipfs.eth.aragon.network/ipfs/bafybeihecaj55qf5tdwifi6qhbybczjwctxwk5vly6doizrvrmiyhd6tfe": "Phishing",
    "http://87.120.115.240/Downloads/aviso-4-derecho-de-preferencia2017.pdf.lnk": "Phishing",
    "https://pro-vp-onet.weebly.com/": "Phishing",
    "https://dk11863367715.activehosted.com/f/1": "Phishing",
    "https://hketoll-k.top/": "Phishing",
    "https://vk.com/away.php?to=https://www.newlifenursery.com/assets/rdt.html?key=LwHi1": "Phishing",
    "https://spidyconnectfr.firebaseapp.com/": "Phishing",
    "http://www.univer.oss-ap-northeast-2.aliyuncs.com": "Phishing",
    "https://ipfs.io/ipfs/Qmd1wwmsBmQnGoHd5EQdtNdbaVMcnYxpKMQUeRPSsSQ3pa": "Phishing",
    "https://ipfs.eth.aragon.network/ipfs/bafybeif5lxemx467vuf3hd75pv72kedinjsm5rqp7iu6re6tmiwsq7z2ze/": "Phishing",
    "https://www.lavozdeloscentauros.com": "Phishing",
    "https://autnethicationservicesdomainhostinghosstingservices1.pages.dev": "Phishing",
    "https://storageapi-stg.fleek.co/76323ce1-bcf2-4691-bb00-b00ce8c0fc5a-bucket/adobe.html": "Phishing",
    "https://portalusuariospostpagos.co/transaction/ent/b-34f5/": "Phishing",
    "https://hotmail-105150.weeblysite.com/": "Phishing",
    "https://mxtmsxcrom-extnsion.gitbook.io/us": "Phishing",
    "https://y7f9zzu3.duckdns.org": "Phishing",
    "http://atentic-mp-app-auth.comercial.ws/YN IRoS8IUSgl5eoBFFA3kKMcqx85WM8xwKgUkyeXKS9JccPNoafkqHWMpn/?https://bradesco.com.br": "Phishing",
    "https://pub-4f53d843ef8a4fcf9cb391135ccbcd0f.r2.dev/index.html": "Phishing",
    "http://tinyurl.com/4p7hsfsp": "Phishing",
    "https://t.co/dBopnFQWQl": "Phishing",
    "https://www.sfr-paiement-abonnement.fr/login.php": "Phishing",
    "https://polskdurieyhagshdneyurhjdmamn63748idm904nwhwmeajskmeujd2.pages.dev/": "Phishing",
    "https://bit.ly/4fBivoD": "Phishing",
    "https://telstra-105823.weeblysite.com/": "Phishing",
    "http://103.57.121.123:18519/Mozi.m": "Phishing",
    "https://bafybeiejoq5hgycaiznphgauufgkw2xsruypxzq3hcinr34i76ohnbffse.ipfs.cf-ipfs.com/": "Phishing",
    "https://docs.google.com/presentation/d/e/2PACX-1vRJxmQXvZJ0aFCJEh8a8NmDbPr5PFLBykm385Dba8ahaBNzRWu1u8WttZekybokLiHOWWFXVyetTfCn/pub?start=false&loop=false&delayms=3000": "Phishing",
    "http://www.orchidandiris.com": "Phishing",
    "https://q-r.to/bfFvcI": "Phishing",
    "http://karoonpc.com/Slade107.psm": "Phishing",
    "http://www.longwoodlife.com": "Phishing",
    "https://s.id/1pvol": "Phishing",
    "http://87.120.115.240/Downloads/685.pdf.lnk": "Phishing",
}


all_urls = {}

all_urls.update(test_set_1)
all_urls.update(test_set_2)

print(f"Toplam URL : {len(all_urls)}")


results = []

y_true = []

y_pred = []

times = []

for url, label in all_urls.items():

    true_label = 1 if label == "Phishing" else 0

    start = time.perf_counter()

    features = extract_features(url)

    probability = model.predict_proba(features)[0]

    prediction = int(model.predict(features)[0])

    elapsed = (time.perf_counter() - start) * 1000

    y_true.append(true_label)

    y_pred.append(prediction)

    times.append(elapsed)

    results.append({

        "URL": url,

        "Gerçek Etiket": label,

        "Tahmin": "Phishing" if prediction else "Legitimate",

        "Phishing Olasılığı": round(probability[1], 4),

        "Legitimate Olasılığı": round(probability[0], 4),

        "Tahmin Süresi (ms)": round(elapsed, 3),

        "Doğru Tahmin":
            "Evet" if prediction == true_label else "Hayır"

    })


# =========PERFORMANS==========

accuracy = accuracy_score(y_true, y_pred)

precision = precision_score(y_true, y_pred)

recall = recall_score(y_true, y_pred)

f1 = f1_score(y_true, y_pred)

tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()


summary = pd.DataFrame({

    "Metrik":[

        "Toplam URL",

        "Doğru Tahmin",

        "Yanlış Tahmin",

        "Accuracy (%)",

        "Precision",

        "Recall",

        "F1 Score",

        "True Positive",

        "True Negative",

        "False Positive",

        "False Negative",

        "Ortalama Süre (ms)",

        "Minimum Süre (ms)",

        "Maksimum Süre (ms)"

    ],

    "Değer":[

        len(all_urls),

        sum(a==b for a,b in zip(y_true,y_pred)),

        len(all_urls)-sum(a==b for a,b in zip(y_true,y_pred)),

        round(accuracy*100,2),

        round(precision,4),

        round(recall,4),

        round(f1,4),

        tp,

        tn,

        fp,

        fn,

        round(sum(times)/len(times),3),

        round(min(times),3),

        round(max(times),3)

    ]

})


# ======CONFUSION MATRIX======

cm = pd.DataFrame(

    [[tn, fp],
     [fn, tp]],

    index=["Gerçek Legitimate",
           "Gerçek Phishing"],

    columns=["Tahmin Legitimate",
             "Tahmin Phishing"]

)




detail = pd.DataFrame(results)

with pd.ExcelWriter(
        "C:/Users/USER/Desktop/URL/Phishing-Detection/thesis/tables/Performance_Report.xlsx",
        engine="openpyxl") as writer:

    summary.to_excel(

        writer,

        sheet_name="Performance Summary",

        index=False

    )

    detail.to_excel(

        writer,

        sheet_name="Detailed Results",

        index=False

    )

    cm.to_excel(

        writer,

        sheet_name="Confusion Matrix"

    )

print("\n")
print("="*60)

print("MODEL PERFORMANSI")

print("="*60)

print(summary)

print("="*60)

print("\nExcel dosyası oluşturuldu.")

print("Dosya : Performance_Report.xlsx")