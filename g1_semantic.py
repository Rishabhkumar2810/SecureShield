"""
g1_semantic.py
---------------
G1 - Semantic Opcode Chromosome Strand  (SecureStrand AI / "Semantic Oracle" agent A-03)

Pipeline:
  1. Scan every method's decompiled instructions for API calls belonging to
     known "sensitive categories" (UI credential input, local storage,
     network send, crypto, reflection/dynamic code loading)
  2. Build a per-method "opcode intent chain" — the ORDER these categories
     appear in — and match it against known malicious sequences
     (e.g. UI_CREDENTIAL_READ -> NETWORK_SEND with no CRYPTO step in
     between = plaintext credential exfiltration)
  3. LLM reasoning layer -> Claude reads the flagged method and answers
     "what is this code trying to accomplish?", explicitly reasoning past
     obfuscated/meaningless variable names, and runs a lightweight
     counterfactual check ("would a benign banking app plausibly need
     this exact sequence?")
  4. Fuse into a single 0-100 score in the standard strand schema

Requires: anthropic  (pip install anthropic --break-system-packages)

NOTE: The design doc describes "LLM code embedding + Graph Neural Network."
A production GNN over a full program dependence graph is out of scope for
a hackathon build. This implementation gets the same *signal* — intent-level
reasoning over API call sequences — via direct LLM reasoning instead of a
trained GNN, which is a defensible and honestly-scoped simplification.
"""

import json
import re
from anthropic import Anthropic

# ----------------------------------------------------------------------
# API categories used to build each method's "opcode intent chain."
# Match strings are checked against androguard's instruction output text,
# which includes the fully-qualified method being invoked.
# ----------------------------------------------------------------------
API_CATEGORIES = {
    "UI_CREDENTIAL_READ": [
        "Landroid/widget/EditText;->getText",
        "Landroid/widget/TextView;->getText",
        "Landroid/webkit/WebView;->evaluateJavascript",
    ],
    "STORAGE_READ": [
        "Landroid/content/SharedPreferences;->get",
        "Landroid/database/sqlite/SQLiteDatabase;->query",
        "Ljava/io/FileInputStream;",
    ],
    "STORAGE_WRITE": [
        "Landroid/content/SharedPreferences$Editor;->put",
        "Ljava/io/FileOutputStream;",
    ],
    "NETWORK_SEND": [
        "Ljava/net/HttpURLConnection;",
        "Lokhttp3/",
        "Ljava/net/Socket;",
        "Ljava/net/URL;->openConnection",
        "Landroid/telephony/SmsManager;->sendTextMessage",
    ],
    "CRYPTO": [
        "Ljavax/crypto/Cipher;",
        "Ljava/security/MessageDigest;",
        "Ljavax/crypto/spec/SecretKeySpec;",
    ],
    "REFLECTION_OBFUSCATION": [
        "Ljava/lang/Class;->forName",
        "Ljava/lang/reflect/Method;->invoke",
        "Ldalvik/system/DexClassLoader;",
        "Ldalvik/system/PathClassLoader;",
    ],
    "ACCESSIBILITY_READ": [
        "Landroid/accessibilityservice/AccessibilityService;",
        "Landroid/view/accessibility/AccessibilityNodeInfo;",
    ],
}

# Known malicious intent chains: if a method's category sequence contains
# this SUBSEQUENCE (order matters, gaps allowed), flag it with the given
# risk description and weight.
MALICIOUS_SEQUENCES = [
    {
        "sequence": ["UI_CREDENTIAL_READ", "NETWORK_SEND"],
        "excludes": ["CRYPTO"],
        "risk": "Credential harvest: reads user input directly then sends over network with no encryption step",
        "weight": 35,
    },
    {
        "sequence": ["ACCESSIBILITY_READ", "NETWORK_SEND"],
        "excludes": [],
        "risk": "Accessibility-based screen scraping followed by network exfiltration",
        "weight": 35,
    },
    {
        "sequence": ["STORAGE_READ", "NETWORK_SEND"],
        "excludes": [],
        "risk": "Reads locally stored data (prefs/DB/files) then transmits it over network",
        "weight": 20,
    },
    {
        "sequence": ["REFLECTION_OBFUSCATION", "NETWORK_SEND"],
        "excludes": [],
        "risk": "Uses reflection/dynamic class loading to obscure code that ultimately sends data over network",
        "weight": 25,
    },
]


class G1SemanticAnalyzer:
    def __init__(self, extractor, anthropic_api_key: str = None, use_llm: bool = True):
        self.extractor = extractor
        self.use_llm = use_llm
        self.client = Anthropic(api_key=anthropic_api_key) if use_llm else None

    # --------------------------------------------------------------
    def analyze(self) -> dict:
        methods = self.extractor.get_all_methods_source()

        flagged_methods = self._build_intent_chains(methods)
        matched_sequences = self._match_malicious_sequences(flagged_methods)

        rule_score = self._rule_based_score(matched_sequences)

        llm_result = {"score": rule_score, "intent_labels": []}
        if self.use_llm and matched_sequences:
            llm_result = self._llm_reasoning(matched_sequences[:5])

        final_score = round(0.45 * rule_score + 0.55 * llm_result["score"])
        final_score = max(0, min(100, final_score))

        evidence = self._build_evidence(matched_sequences, llm_result)

        return {
            "strand": "G1",
            "score": final_score,
            "evidence": evidence,
            "raw_features": {
                "total_methods_scanned": len(methods),
                "methods_with_sensitive_api_chains": len(flagged_methods),
                "matched_malicious_sequences": [
                    {
                        "method": m["full_signature"],
                        "chain": m["category_chain"],
                        "risk": m["risk"],
                    } for m in matched_sequences
                ],
                "intent_labels": llm_result.get("intent_labels", []),
            }
        }

    # --------------------------------------------------------------
    def _build_intent_chains(self, methods):
        """For each method, walk its instructions in order and record which
        API category each matched call belongs to — this ordered list IS
        the 'opcode intent chain' (a lightweight stand-in for a full
        control-flow-graph embedding)."""
        flagged = []
        for m in methods:
            code_text_lines = m["code_lines"]
            chain = []
            for line in code_text_lines:
                for category, patterns in API_CATEGORIES.items():
                    if any(p in line for p in patterns):
                        chain.append(category)
                        break
            if chain:
                m["category_chain"] = chain
                m["code_snippet"] = "\n".join(code_text_lines[:40])
                flagged.append(m)
        return flagged

    # --------------------------------------------------------------
    def _match_malicious_sequences(self, flagged_methods):
        matched = []
        for m in flagged_methods:
            chain = m["category_chain"]
            for seq_def in MALICIOUS_SEQUENCES:
                if self._is_subsequence(seq_def["sequence"], chain) and \
                   not any(ex in chain for ex in seq_def["excludes"]):
                    matched.append({
                        "full_signature": m["full_signature"],
                        "category_chain": chain,
                        "code_snippet": m["code_snippet"],
                        "risk": seq_def["risk"],
                        "weight": seq_def["weight"],
                    })
                    break  # one match per method is enough for scoring
        return matched

    @staticmethod
    def _is_subsequence(pattern, chain):
        """Checks if `pattern` appears as an in-order subsequence of `chain`
        (gaps allowed) — e.g. ['A','B'] matches chain ['A','X','B']."""
        it = iter(chain)
        return all(p in it for p in pattern)

    # --------------------------------------------------------------
    def _rule_based_score(self, matched_sequences):
        score = sum(m["weight"] for m in matched_sequences[:4])
        return min(100, score)

    # --------------------------------------------------------------
    def _llm_reasoning(self, matched_sequences):
        prompt = f"""You are the Semantic Oracle agent in a banking-malware detection pipeline.
You reason over decompiled Android bytecode to determine INTENT, ignoring obfuscated or
meaningless variable/class names — focus on what the sequence of API calls actually accomplishes.

Below are methods our static engine flagged for suspicious API call sequences:
{json.dumps([{"method": m["full_signature"], "category_chain": m["category_chain"], "flagged_risk": m["risk"], "code": m["code_snippet"][:1500]} for m in matched_sequences], indent=2)}

For each method:
1. State in one sentence what the code is trying to accomplish (its semantic intent)
2. Apply a counterfactual check: would a BENIGN banking/UPI app plausibly need this exact
   sequence of calls for a legitimate feature (e.g. auto-fill, analytics)? If not, explain why
   this looks malicious rather than incidental.
3. Assign an intent label from: ["credential_harvest", "data_exfiltration", "screen_scraping",
   "obfuscated_exfiltration", "benign_likely", "inconclusive"]

Then give an overall score 0-100 for how strongly these methods collectively indicate
malicious credential-harvesting intent.

Respond with ONLY valid JSON, no preamble, no markdown fences:
{{
  "score": <int 0-100>,
  "intent_labels": [
    {{"method": "<signature>", "intent": "<one sentence>", "counterfactual": "<one sentence>", "label": "<label>"}}
  ]
}}"""

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(block.text for block in response.content if block.type == "text")
            text = re.sub(r"```json|```", "", text).strip()
            parsed = json.loads(text)
            parsed["score"] = max(0, min(100, int(parsed.get("score", 0))))
            return parsed
        except Exception as e:
            return {"score": 0, "intent_labels": [], "error": str(e)}

    # --------------------------------------------------------------
    def _build_evidence(self, matched_sequences, llm_result):
        evidence = []
        for label in llm_result.get("intent_labels", [])[:3]:
            evidence.append(
                f"{label.get('label')}: {label.get('intent')} — {label.get('counterfactual')}"
            )

        for m in matched_sequences[:2]:
            chain_str = " -> ".join(m["category_chain"])
            evidence.append(f"Opcode chain [{chain_str}] in {m['full_signature'].split('->')[-1]} — {m['risk']}")

        if not evidence:
            evidence.append("No malicious semantic opcode chains detected")

        return evidence[:6]


if __name__ == "__main__":
    import sys
    from apk_extractor import APKExtractor

    if len(sys.argv) < 2:
        print("Usage: python g1_semantic.py <path_to_apk> [anthropic_api_key]")
        sys.exit(1)

    apk_path = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 else None

    extractor = APKExtractor(apk_path)
    analyzer = G1SemanticAnalyzer(extractor, anthropic_api_key=api_key, use_llm=bool(api_key))
    result = analyzer.analyze()
    print(json.dumps(result, indent=2))
