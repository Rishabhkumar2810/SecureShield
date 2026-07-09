"""
g3_linguistic_strand.py
------------------------
G3 - Linguistic Social Engineering Strand

Captures: UI strings, dialog text, phishing language patterns.
AI techniques (target state): fine-tuned LLM sentiment + deception classifier.
This module implements a working v1 (lexicon + typosquat + structural heuristics)
and a clearly marked hook for the LLM deep-pass described in the SSA doc.

Corresponds to Agent A-05 "Phish Linguist" in the SSA architecture.
"""

import re
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from Levenshtein import distance as levenshtein_distance

from genome_common import LoadedAPK, build_strand_output, safe_load_apk, to_json

# ---------------------------------------------------------------------------
# 1. LEXICONS
#    Each category has a weight reflecting how strongly it correlates with
#    banking social-engineering (tuned against the doc's banking-sector
#    weighting philosophy in section 5). Extend these lists from real
#    phishing-SMS/UI corpora as you collect data.
# ---------------------------------------------------------------------------

LEXICON: Dict[str, Dict[str, float]] = {
    "urgency": {
        "weight": 3.0,
        "terms": [
            "immediately", "urgent", "act now", "expires today", "final notice",
            "within 24 hours", "within 1 hour", "your account will be",
            "will be blocked", "will be suspended", "last warning",
        ],
    },
    "threat_authority": {
        "weight": 3.5,
        "terms": [
            "account suspended", "account blocked", "unauthorized access",
            "suspicious activity detected", "account locked", "security alert",
            "rbi", "cert-in", "government notice", "legal action", "penalty",
        ],
    },
    "credential_solicitation": {
        "weight": 4.0,
        "terms": [
            "enter otp", "enter your pin", "enter upi pin", "enter cvv",
            "confirm your password", "update your kyc", "verify your account",
            "enter card number", "enter atm pin", "share otp",
        ],
    },
    "reward_lure": {
        "weight": 2.0,
        "terms": [
            "claim now", "cashback", "you have won", "limited time offer",
            "congratulations", "free reward", "click to claim",
        ],
    },
    "brand_official_mimicry": {
        "weight": 2.5,
        "terms": [
            "official app", "authorized by", "verified by bank",
            "customer care", "toll free", "helpline",
        ],
    },
}

# Known Indian banking brands to check for typosquatting (extend from RBI list)
KNOWN_BANK_BRANDS: List[str] = [
    "sbi", "hdfc", "icici", "axis bank", "kotak", "pnb", "bank of baroda",
    "canara bank", "union bank", "paytm", "phonepe", "google pay", "bhim upi",
]

TYPOSQUAT_MAX_DISTANCE = 2   # edit distance <= this => flagged as near-match
TYPOSQUAT_MIN_BRAND_LEN = 5  # short brands (sbi, pnb) are excluded: at distance<=2
                              # almost any 3-letter word matches them, which is pure
                              # noise. Handle short brands with an exact/substring
                              # check instead (see detect_typosquatting below).
TYPOSQUAT_MIN_TOKEN_LEN = 5   # don't compare against very short candidate tokens either


# ---------------------------------------------------------------------------
# 2. STRING EXTRACTION
#    Pulls text from every surface a user actually sees: resource strings,
#    layout XML text attributes, and hardcoded DEX string-pool constants
#    (many phishing apps deliberately hardcode strings to dodge strings.xml
#    scanners, so skipping the DEX pool would miss real-world samples).
# ---------------------------------------------------------------------------

def _flatten_string_leaves(obj) -> List[str]:
    """
    androguard's get_resolved_strings() returns a nested structure
    (package -> locale -> resource_id -> value) and the leaf `value` is
    sometimes itself a str, and sometimes a dict/list (e.g. plurals or
    styled text spans). Walk defensively and only keep actual str leaves.
    """
    out = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_flatten_string_leaves(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_flatten_string_leaves(v))
    return out


def extract_resource_strings(loaded: LoadedAPK) -> List[str]:
    strings = []
    try:
        # androguard exposes parsed string resources per-locale
        res = loaded.apk.get_android_resources()
        if res:
            try:
                string_dict = res.get_resolved_strings()
                if string_dict:
                    strings.extend(_flatten_string_leaves(string_dict))
            except Exception:
                pass
    except Exception:
        pass
    return strings


def extract_layout_text_attrs(loaded: LoadedAPK) -> List[str]:
    strings = []
    try:
        for fname in loaded.apk.get_files():
            if fname.startswith("res/layout") and fname.endswith(".xml"):
                try:
                    xml = loaded.apk.get_android_resources().get_xml_from_string(
                        loaded.apk.get_file(fname)
                    ) if hasattr(loaded.apk.get_android_resources(), "get_xml_from_string") else None
                except Exception:
                    xml = None
                # Fallback: androguard's get_file gives raw AXML bytes; use
                # get_android_resources().decode_str or apk.get_file + AXMLPrinter
                try:
                    from androguard.core.axml import AXMLPrinter
                    raw = loaded.apk.get_file(fname)
                    axml = AXMLPrinter(raw)
                    text = axml.get_buff().decode("utf-8", errors="ignore")
                    strings += re.findall(r'android:text="([^"]+)"', text)
                except Exception:
                    continue
    except Exception:
        pass
    return strings


def extract_dex_string_pool(loaded: LoadedAPK, min_len: int = 4) -> List[str]:
    """
    Pull const-string literals directly from the DEX string pool. This is the
    most important source for evasive phishing apps that build UI text
    programmatically instead of via strings.xml.
    """
    strings = []
    for dvm in loaded.dvm_list:
        try:
            for s in dvm.get_strings():
                if s and len(s) >= min_len and _looks_like_human_text(s):
                    strings.append(s)
        except Exception:
            continue
    return strings


def _looks_like_human_text(s: str) -> bool:
    """Filter out class names, package paths, and pure symbol noise."""
    if "/" in s and "." in s and s.count("/") > 1:
        return False  # likely a class/package path e.g. Lcom/foo/bar;
    if re.fullmatch(r"[A-Za-z0-9_./;$\[\]]+", s) and " " not in s and len(s) < 30:
        return False  # likely an identifier, not user-facing prose
    return bool(re.search(r"[A-Za-z]{3,}", s))


def collect_all_strings(loaded: LoadedAPK) -> List[str]:
    all_strings = []
    all_strings += extract_resource_strings(loaded)
    all_strings += extract_layout_text_attrs(loaded)
    all_strings += extract_dex_string_pool(loaded)
    # de-dupe while preserving order
    seen: Set[str] = set()
    out = []
    for s in all_strings:
        if not isinstance(s, str):
            continue
        key = s.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(s.strip())
    return out


# ---------------------------------------------------------------------------
# 3. LEXICON SCORING
# ---------------------------------------------------------------------------

def score_lexicon(strings: List[str]) -> Tuple[float, List[str], Dict[str, int]]:
    evidence = []
    category_hits = defaultdict(int)
    raw_score = 0.0
    lowered_strings = [(s, s.lower()) for s in strings]

    for category, spec in LEXICON.items():
        weight = spec["weight"]
        for term in spec["terms"]:
            for original, low in lowered_strings:
                if term in low:
                    category_hits[category] += 1
                    raw_score += weight
                    evidence.append(f'{category}: "{original.strip()[:80]}" matched "{term}"')
                    break  # one evidence line per term is enough signal

    return raw_score, evidence, dict(category_hits)


# ---------------------------------------------------------------------------
# 4. TYPOSQUAT / BRAND IMPERSONATION DETECTION
# ---------------------------------------------------------------------------

def detect_typosquatting(strings: List[str], app_label: str = "") -> Tuple[float, List[str], List[Dict]]:
    evidence = []
    hits = []
    score = 0.0

    candidates = strings + ([app_label] if app_label else [])
    tokens: Set[str] = set()
    for s in candidates:
        tokens.update(re.findall(r"[A-Za-z]{3,}", s.lower()))

    for token in tokens:
        for brand in KNOWN_BANK_BRANDS:
            brand_compact = brand.replace(" ", "")

            if len(brand_compact) < TYPOSQUAT_MIN_BRAND_LEN:
                # Short brands (sbi, pnb, ...): edit-distance is too noisy at
                # this length (nearly every 3-letter word is "close" to
                # another). Only flag an EXACT match embedded in a longer
                # token (e.g. "sbi" inside "sbi-verify" or "mysbibank"),
                # which is a much stronger signal than fuzzy distance.
                if len(token) > len(brand_compact) and brand_compact in token:
                    score += 5.0
                    hits.append({"token": token, "brand": brand, "match_type": "substring"})
                    evidence.append(f'brand_impersonation: "{token}" contains brand token "{brand}"')
                continue

            if len(token) < TYPOSQUAT_MIN_TOKEN_LEN:
                continue

            d = levenshtein_distance(token, brand_compact)
            if 0 < d <= TYPOSQUAT_MAX_DISTANCE and abs(len(token) - len(brand_compact)) <= 2:
                score += 6.0
                hits.append({"token": token, "brand": brand, "edit_distance": d})
                evidence.append(f'brand_impersonation: "{token}" is edit-distance {d} from "{brand}"')

    return score, evidence, hits


# ---------------------------------------------------------------------------
# 5. LLM DEEP-PASS HOOK (target-state, per doc: "Fine-tuned LLM sentiment
#    and deception classifier"). Wire this to your Anthropic API call once
#    you have an API key configured; left as a clean extension point so the
#    static v1 above works standalone.
# ---------------------------------------------------------------------------

def llm_deception_pass(ambiguous_strings: List[str]) -> Tuple[float, List[str]]:
    """
    Placeholder for the LLM reasoning pass. Intended prompt shape:

        System: You are a banking-fraud linguistics analyst. For each string,
        output a 0-1 deception probability and a one-line justification,
        looking specifically for urgency, authority impersonation, and
        credential solicitation patterns typical of Indian banking phishing.

    Wire this to api.anthropic.com/v1/messages (model: claude-sonnet-4-6),
    batch the `ambiguous_strings` (those that scored 0 on lexicon but are
    still long/prose-like, since lexicons miss paraphrased phishing), parse
    the structured response, and fold scores back in here.

    Returns (score_contribution, evidence_lines). No-op until wired up.
    """
    return 0.0, []


# ---------------------------------------------------------------------------
# 6. STRAND ENTRY POINT
# ---------------------------------------------------------------------------

def analyze_g3(apk_path: str) -> Dict:
    loaded = safe_load_apk(apk_path)
    if loaded.error:
        return build_strand_output(
            strand="G3",
            score=0,
            evidence=[f"ERROR loading APK: {loaded.error}"],
            raw_features={"load_error": loaded.error},
        )

    app_label = ""
    try:
        app_label = loaded.apk.get_app_name() or ""
    except Exception:
        pass

    strings = collect_all_strings(loaded)

    lex_score, lex_evidence, category_hits = score_lexicon(strings)
    typo_score, typo_evidence, typo_hits = detect_typosquatting(strings, app_label)
    llm_score, llm_evidence = llm_deception_pass(
        [s for s in strings if len(s) > 25 and lex_score == 0]
    )

    total_raw = lex_score + typo_score + llm_score
    # Normalize: cap contribution so a few matches don't instantly max the
    # strand; this constant is a tuning knob, calibrate against labeled data.
    normalized_score = min(100, total_raw * 2.2)

    evidence = lex_evidence + typo_evidence + llm_evidence
    if not evidence:
        evidence = ["No social-engineering language patterns detected in extracted UI strings."]

    raw_features = {
        "total_strings_extracted": len(strings),
        "lexicon_category_hits": category_hits,
        "lexicon_raw_score": round(lex_score, 2),
        "typosquat_hits": typo_hits,
        "typosquat_raw_score": round(typo_score, 2),
        "app_label": app_label,
    }

    return build_strand_output("G3", normalized_score, evidence, raw_features)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python g3_linguistic_strand.py <path_to_apk>")
        sys.exit(1)
    result = analyze_g3(sys.argv[1])
    print(to_json(result))
