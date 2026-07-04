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