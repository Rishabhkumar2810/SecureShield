"""
g4_network.py
--------------
G4 - Network Behavior Helix Strand  (SecureStrand AI / "Net Shadow" agent A-06)

Pipeline:
  1. Extract every URL, domain, and IP address literal embedded in the
     APK's strings/code (not just UI text — hidden C&C endpoints usually
     aren't shown to the user)
  2. Extract which raw network APIs are used (HttpURLConnection, OkHttp,
     raw Socket/DatagramSocket — the latter is a covert-channel signal
     since legitimate banking apps almost always use HTTPS libraries)
  3. Score each domain/IP using cheap anomaly heuristics: Shannon entropy
     (DGA-style random domains have high entropy), hardcoded raw IPs
     (legit apps essentially never hardcode IP literals), non-standard
     ports, suspicious TLDs
  4. LLM reasoning layer -> Claude looks at the full endpoint list + API
     usage pattern together and reasons about C&C likelihood / covert
     channel usage
  5. Fuse into a single 0-100 score in the standard strand schema

Requires: anthropic  (pip install anthropic --break-system-packages)

NOTE: This is a static, offline analysis — it does NOT perform live DNS
resolution, WHOIS lookups, or threat-intel API calls (VirusTotal, etc.).
Wiring in one of those live feeds is the natural next step for production
and would strengthen the C&C fingerprint match well beyond what's possible
from the APK alone.
"""

import json
import math
import re
from anthropic import Anthropic

URL_REGEX = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')

RAW_SOCKET_APIS = ["Ljava/net/Socket;", "Ljava/net/DatagramSocket;", "Ljava/net/DatagramPacket;"]
HTTP_LIB_APIS = ["Ljava/net/HttpURLConnection;", "Lokhttp3/", "Lorg/apache/http/"]

SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".gq", ".tk", ".ml", ".cf", ".ga", ".icu"]

# Legitimate infra domains that show up in almost every app — excluded from
# scoring so they don't create noise.
COMMON_BENIGN_DOMAINS = [
    "google.com", "googleapis.com", "gstatic.com", "android.com",
    "firebaseio.com", "crashlytics.com", "facebook.com", "doubleclick.net",
    "w3.org", "schemas.android.com", "apache.org", "xmlpull.org",
]


class G4NetworkAnalyzer:
    def __init__(self, extractor, anthropic_api_key: str = None, use_llm: bool = True):
        self.extractor = extractor
        self.use_llm = use_llm
        self.client = Anthropic(api_key=anthropic_api_key) if use_llm else None

    # --------------------------------------------------------------
    def analyze(self) -> dict:
        all_strings = self.extractor.get_all_literal_strings()
        methods = self.extractor.get_all_methods_source()

        urls, domains, ips = self._extract_network_indicators(all_strings)
        uses_raw_sockets = self._check_raw_socket_usage(methods)

        scored_domains = self._score_domains(domains)
        scored_ips = self._score_ips(ips)

        rule_score = self._rule_based_score(scored_domains, scored_ips, uses_raw_sockets)

        llm_result = {"score": rule_score, "assessments": []}
        if self.use_llm and (scored_domains or scored_ips or uses_raw_sockets):
            llm_result = self._llm_reasoning(urls, scored_domains, scored_ips, uses_raw_sockets)

        final_score = round(0.4 * rule_score + 0.6 * llm_result["score"])
        final_score = max(0, min(100, final_score))

        evidence = self._build_evidence(scored_domains, scored_ips, uses_raw_sockets, llm_result)

        return {
            "strand": "G4",
            "score": final_score,
            "evidence": evidence,
            "raw_features": {
                "total_urls_found": len(urls),
                "total_domains_found": len(domains),
                "total_hardcoded_ips_found": len(ips),
                "uses_raw_socket_apis": uses_raw_sockets,
                "flagged_domains": scored_domains[:15],
                "flagged_ips": scored_ips[:15],
                "sample_urls": sorted(urls)[:20],
                "llm_assessments": llm_result.get("assessments", []),
            }
        }

    # --------------------------------------------------------------
    def _extract_network_indicators(self, all_strings):
        urls, domains, ips = set(), set(), set()
        for s in all_strings:
            for m in URL_REGEX.findall(s):
                urls.add(m)
            for m in DOMAIN_REGEX.findall(s):
                if not any(m.endswith(b) for b in COMMON_BENIGN_DOMAINS):
                    domains.add(m.lower())
            for m in IPV4_REGEX.findall(s):
                if not m.startswith(("127.", "0.", "255.")):
                    ips.add(m)
        return urls, domains, ips

    def _check_raw_socket_usage(self, methods):
        for m in methods:
            code_text = "\n".join(m["code_lines"])
            if any(api in code_text for api in RAW_SOCKET_APIS):
                return True
        return False

    # --------------------------------------------------------------
    @staticmethod
    def _shannon_entropy(s):
        if not s:
            return 0.0
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(s)
            entropy -= p * math.log2(p)
        return entropy

    def _score_domains(self, domains):
        scored = []
        for d in domains:
            label = d.split(".")[0]
            entropy = self._shannon_entropy(label)
            reasons = []
            risk = 0
            if entropy > 3.5 and len(label) > 8:
                reasons.append("high entropy label (DGA-like random string)")
                risk += 30
            if any(d.endswith(tld) for tld in SUSPICIOUS_TLDS):
                reasons.append("uses a TLD commonly abused for disposable/cheap malicious domains")
                risk += 20
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', d):
                reasons.append("raw IP used where a domain was expected")
                risk += 15
            if reasons:
                scored.append({"domain": d, "entropy": round(entropy, 2), "risk_score": risk, "reasons": reasons})
        return sorted(scored, key=lambda x: -x["risk_score"])

    def _score_ips(self, ips):
        # Any hardcoded IP is at least mildly suspicious for a modern banking
        # app (legit apps use DNS-resolved hostnames, not literal IPs, so
        # they can rotate infrastructure and use TLS/cert pinning cleanly).
        return [{"ip": ip, "risk_score": 20, "reason": "hardcoded raw IP literal in code/strings"} for ip in sorted(ips)]

    # --------------------------------------------------------------
    def _rule_based_score(self, scored_domains, scored_ips, uses_raw_sockets):
        score = 0
        score += sum(d["risk_score"] for d in scored_domains[:3])
        score += sum(i["risk_score"] for i in scored_ips[:3])
        if uses_raw_sockets:
            score += 20
        return min(100, score)

    # --------------------------------------------------------------
    def _llm_reasoning(self, urls, scored_domains, scored_ips, uses_raw_sockets):
        prompt = f"""You are the Net Shadow agent in a banking-malware detection pipeline,
analyzing an Android APK's network behavior from static artifacts only (no live traffic).

URLs found embedded in the app: {json.dumps(sorted(urls)[:20])}
Domains flagged by heuristics (entropy/TLD/pattern analysis): {json.dumps(scored_domains[:10], indent=2)}
Hardcoded raw IP addresses found: {json.dumps(scored_ips[:10], indent=2)}
App uses raw Socket/DatagramSocket APIs (vs standard HTTPS libraries): {uses_raw_sockets}

Task: Reason about whether this network behavior pattern is consistent with a
Command-and-Control (C&C) channel or covert data exfiltration, versus normal
legitimate app infrastructure (analytics SDKs, payment gateways, CDNs).
Consider: raw sockets bypass standard TLS/certificate-pinning inspection and
are unusual for banking apps; high-entropy domains suggest algorithmically
generated C&C infrastructure; hardcoded IPs bypass DNS-based blocklisting.

Rate 0-100 how strongly this network behavior indicates malicious C&C/covert
channel activity.

Respond with ONLY valid JSON, no preamble, no markdown fences:
{{
  "score": <int 0-100>,
  "assessments": [
    "<one sentence reasoning point>",
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
            return {"score": 0, "assessments": [], "error": str(e)}

    # --------------------------------------------------------------
    def _build_evidence(self, scored_domains, scored_ips, uses_raw_sockets, llm_result):
        evidence = []

        for d in scored_domains[:2]:
            evidence.append(f"Suspicious domain '{d['domain']}' — {', '.join(d['reasons'])}")

        for ip in scored_ips[:2]:
            evidence.append(f"Hardcoded IP '{ip['ip']}' found in code — {ip['reason']}")

        if uses_raw_sockets:
            evidence.append("App uses raw Socket/DatagramSocket APIs instead of standard HTTPS libraries — possible covert channel")

        for line in llm_result.get("assessments", [])[:2]:
            evidence.append(line)

        if not evidence:
            evidence.append("No suspicious network endpoints or covert channel indicators detected")

        return evidence[:6]


if __name__ == "__main__":
    import sys
    from apk_extractor import APKExtractor

    if len(sys.argv) < 2:
        print("Usage: python g4_network.py <path_to_apk> [anthropic_api_key]")
        sys.exit(1)

    apk_path = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 else None

    extractor = APKExtractor(apk_path)
    analyzer = G4NetworkAnalyzer(extractor, anthropic_api_key=api_key, use_llm=bool(api_key))
    result = analyzer.analyze()
    print(json.dumps(result, indent=2))
