"""
g2_permission.py
------------------
G2 - Permission Intent Graph Strand  (SecureStrand AI / "Permission Graph AI" agent A-04)

Pipeline:
  1. Pull declared permissions + which ones are actually exercised in code
     (over-permissioning signal) from apk_extractor
  2. Build a causality graph of KNOWN dangerous permission combinations
     (e.g. ACCESSIBILITY_SERVICE + READ_SMS + INTERNET = credential harvest
     + exfil chain) using networkx
  3. Score based on which dangerous chains are present + how "wired together"
     they are (graph edges connected, not just isolated permissions)
  4. LLM reasoning layer -> Claude explains the causal intent behind the
     specific permission combination found in THIS app
  5. Fuse into a single 0-100 score in the standard strand schema

Requires: networkx, anthropic  (pip install networkx anthropic --break-system-packages)
"""

import json
import re
import networkx as nx
from anthropic import Anthropic

# ----------------------------------------------------------------------
# Known dangerous permission combinations, modeled as a directed causal
# graph: each edge = "permission A enables/feeds into permission B's abuse
# potential". This is the "Permission Intent Graph" — extend freely.
# ----------------------------------------------------------------------
DANGEROUS_COMBOS = [
    {
        "name": "overlay_credential_theft",
        "permissions": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"],
        "risk": "Overlay attack — draws fake login screens on top of real banking apps to steal credentials",
        "weight": 30,
    },
    {
        "name": "otp_interception",
        "permissions": ["RECEIVE_SMS", "READ_SMS", "INTERNET"],
        "risk": "OTP/2FA interception — reads incoming SMS codes and exfiltrates them over the network",
        "weight": 30,
    },
    {
        "name": "accessibility_full_control",
        "permissions": ["BIND_ACCESSIBILITY_SERVICE", "READ_SMS", "INTERNET"],
        "risk": "Full device takeover — accessibility service reads screen content and SMS, exfiltrates via network",
        "weight": 35,
    },
    {
        "name": "silent_dropper",
        "permissions": ["REQUEST_INSTALL_PACKAGES", "INTERNET"],
        "risk": "Dropper behavior — downloads and silently installs additional payloads post-infection",
        "weight": 20,
    },
    {
        "name": "call_redirection_fraud",
        "permissions": ["CALL_PHONE", "PROCESS_OUTGOING_CALLS"],
        "risk": "Call redirection fraud — intercepts or redirects outgoing calls (used to hijack bank verification calls)",
        "weight": 25,
    },
    {
        "name": "smishing_spread",
        "permissions": ["READ_CONTACTS", "SEND_SMS"],
        "risk": "Smishing propagation — harvests contacts and sends phishing SMS to spread further",
        "weight": 18,
    },
    {
        "name": "device_admin_lock",
        "permissions": ["BIND_DEVICE_ADMIN"],
        "risk": "Device admin abuse — can lock/wipe device or block uninstallation (ransomware-style persistence)",
        "weight": 22,
    },
    {
        "name": "background_location_exfil",
        "permissions": ["ACCESS_BACKGROUND_LOCATION", "INTERNET"],
        "risk": "Covert location tracking and exfiltration in the background",
        "weight": 12,
    },
]

# Permission name normalization — androguard returns fully qualified names
# like "android.permission.READ_SMS"; we match on the short suffix.
def _short(perm):
    return perm.split(".")[-1]


class G2PermissionAnalyzer:
    def __init__(self, extractor, anthropic_api_key: str = None, use_llm: bool = True):
        self.extractor = extractor
        self.use_llm = use_llm
        self.client = Anthropic(api_key=anthropic_api_key) if use_llm else None

    # --------------------------------------------------------------
    def analyze(self) -> dict:
        declared = self.extractor.get_declared_permissions()
        used = self.extractor.get_used_permissions()
        declared_short = {_short(p) for p in declared}
        used_short = {_short(p) for p in used} if used else set()

        graph, matched_combos = self._build_intent_graph(declared_short)
        over_permissioned = self._find_over_permissioning(declared_short, used_short)

        rule_score = self._rule_based_score(matched_combos, over_permissioned, declared_short)

        llm_result = {"score": rule_score, "reasoning": []}
        if self.use_llm and matched_combos:
            llm_result = self._llm_reasoning(declared_short, matched_combos)

        final_score = round(0.5 * rule_score + 0.5 * llm_result["score"])
        final_score = max(0, min(100, final_score))

        evidence = self._build_evidence(matched_combos, over_permissioned, llm_result)

        return {
            "strand": "G2",
            "score": final_score,
            "evidence": evidence,
            "raw_features": {
                "total_permissions_declared": len(declared_short),
                "declared_permissions": sorted(declared_short),
                "permissions_actually_used": sorted(used_short),
                "over_permissioned": sorted(over_permissioned),
                "dangerous_combos_matched": [
                    {"name": c["name"], "permissions": c["permissions"], "risk": c["risk"]}
                    for c in matched_combos
                ],
                "graph_edge_count": graph.number_of_edges(),
                "graph_node_count": graph.number_of_nodes(),
                "llm_reasoning": llm_result.get("reasoning", []),
            }
        }

    # --------------------------------------------------------------
    def _build_intent_graph(self, declared_short):
        """Builds a networkx graph where nodes = permissions this app declared,
        and edges connect permissions that co-occur in a known dangerous combo.
        Returns (graph, list_of_matched_combo_dicts)."""
        graph = nx.DiGraph()
        matched_combos = []

        for combo in DANGEROUS_COMBOS:
            combo_perms = set(combo["permissions"])
            if combo_perms.issubset(declared_short):
                matched_combos.append(combo)
                perms_list = list(combo_perms)
                for p in perms_list:
                    graph.add_node(p)
                # connect them pairwise to represent the causal chain
                for i in range(len(perms_list) - 1):
                    graph.add_edge(perms_list[i], perms_list[i + 1], combo=combo["name"])

        return graph, matched_combos

    # --------------------------------------------------------------
    def _find_over_permissioning(self, declared_short, used_short):
        """Permissions requested but never exercised in code — a classic
        red flag (apps request more than they need to look 'normal' while
        keeping unused capability in reserve, or obfuscate the actual usage)."""
        sensitive = {
            "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "CALL_PHONE",
            "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "CAMERA",
            "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_PHONE_STATE",
        }
        if not used_short:
            return set()  # extractor couldn't determine usage — skip this signal
        return {p for p in declared_short if p in sensitive and p not in used_short}

    # --------------------------------------------------------------
    def _rule_based_score(self, matched_combos, over_permissioned, declared_short):
        score = sum(c["weight"] for c in matched_combos)
        score += min(len(over_permissioned), 4) * 5
        return min(100, score)

    # --------------------------------------------------------------
    def _llm_reasoning(self, declared_short, matched_combos):
        prompt = f"""You are the Permission Graph AI agent in a banking-malware detection pipeline.

This Android app declares these permissions:
{json.dumps(sorted(declared_short), indent=2)}

Our rule engine already matched these known dangerous permission combinations:
{json.dumps([{"combo": c["name"], "permissions": c["permissions"], "known_risk": c["risk"]} for c in matched_combos], indent=2)}

Task: Reason causally about what this SPECIFIC combination of permissions lets the app do
end-to-end (e.g. "reads SMS -> combined with INTERNET -> can exfiltrate OTPs to a remote server").
Rate 0-100 how strongly this permission set, taken together, indicates malicious banking-fraud
intent (not just individually risky permissions, but the combination).

Respond with ONLY valid JSON, no preamble, no markdown fences:
{{
  "score": <int 0-100>,
  "reasoning": [
    "<one sentence causal chain explanation>",
    "<another if relevant>"
  ]
}}"""

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=800,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(block.text for block in response.content if block.type == "text")
            text = re.sub(r"```json|```", "", text).strip()
            parsed = json.loads(text)
            parsed["score"] = max(0, min(100, int(parsed.get("score", 0))))
            return parsed
        except Exception as e:
            return {"score": 0, "reasoning": [], "error": str(e)}

    # --------------------------------------------------------------
    def _build_evidence(self, matched_combos, over_permissioned, llm_result):
        evidence = []
        for c in matched_combos[:3]:
            combo_str = " + ".join(c["permissions"])
            evidence.append(f"{combo_str} combo detected — {c['risk']}")

        for line in llm_result.get("reasoning", [])[:2]:
            evidence.append(line)

        if over_permissioned:
            evidence.append(
                f"Over-permissioning: {len(over_permissioned)} sensitive permission(s) declared "
                f"but never exercised in code ({', '.join(sorted(over_permissioned)[:3])})"
            )

        if not evidence:
            evidence.append("No dangerous permission combinations detected")

        return evidence[:6]


if __name__ == "__main__":
    import sys
    from apk_extractor import APKExtractor

    if len(sys.argv) < 2:
        print("Usage: python g2_permission.py <path_to_apk> [anthropic_api_key]")
        sys.exit(1)

    apk_path = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 else None

    extractor = APKExtractor(apk_path)
    analyzer = G2PermissionAnalyzer(extractor, anthropic_api_key=api_key, use_llm=bool(api_key))
    result = analyzer.analyze()
    print(json.dumps(result, indent=2))
