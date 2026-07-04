"""
URL Phishing Detection - Flask API
-----------------------------------
Label mapping:
    Phishing   : 1
    Legitimate : 0
"""

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

app = Flask(__name__)
CORS(app)

MODEL_PATH = "C:/Users/USER/Desktop/URL-Phishing-Detection/model_development/models/XGBoost.joblib"

model = joblib.load(MODEL_PATH)

LABEL_MAP = {1: "Phishing", 0: "Legitimate"}


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


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json(force=True, silent=True) or {}
        url = data.get('url')

        if not url or not isinstance(url, str):
            return jsonify({'error': 'Gecerli bir url alani gerekli'}), 400

        # URL normalizasyonu (veri seti bias duzeltmesi):
        # 1) www. yoksa ekle
        # 2) path sadece / ise kaldir (trailing slash)
        parsed_url = urlparse(_clean_url(url))
        netloc = parsed_url.netloc
        if netloc and not netloc.startswith("www."):
            url = url.replace(netloc, "www." + netloc, 1)
        # Sadece / olan path'i kaldir: https://www.site.com/ -> https://www.site.com
        if url.endswith("/") and url.count("/") == 3:
            url = url.rstrip("/")

        print(f"Gelen URL: {url}")

        features_df = extract_features(url)

        proba = model.predict_proba(features_df)[0]
        phishing_prob = float(proba[1])
        legitimate_prob = float(proba[0])
        prediction = int(model.predict(features_df)[0])
        label = LABEL_MAP.get(prediction, "Unknown")

        result = {
            'prediction': prediction,
            'label': label,
            'probability': {
                'legitimate': legitimate_prob,
                'phishing': phishing_prob,
            }
        }

        print(f"Tahmin Sonucu: {label} ({prediction})")
        return jsonify(result)

    except Exception as e:
        print("\n" + "=" * 50)
        print("HATA DETAYI:")
        print(traceback.format_exc())
        print("=" * 50 + "\n")
        return jsonify({'error': str(e)}), 500
    
    
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    print("Flask Sunucusu Baslatildi! Eklenti artik veri gonderebilir.")
    app.run(debug=True, port=5000)