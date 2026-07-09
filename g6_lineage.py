"""
g6_lineage.py
--------------
G6 - Supply Chain Lineage Strand  (SecureStrand AI / "Lineage Tracer" agent A-08)

Pipeline:
  1. Pull certificate details, embedded library/package fingerprint, and
     repackaging-tool artifacts from apk_extractor
  2. Classify bundled top-level packages against a known-SDK allowlist to
     surface unusual/obfuscated bundled code
  3. (Optional) Structural similarity check against a REFERENCE APK — e.g.
     the real bank's official app — using Jaccard similarity over class-name
     sets. High code similarity + different signing cert = repackaging.
  4. LLM reasoning layer -> Claude synthesizes a provenance narrative:
     "is this a trojanized repackage of a legitimate app?"
  5. Fuse into a single 0-100 score in the standard strand schema

Requires: anthropic  (pip install anthropic --break-system-packages)
"""

import json
import re
from anthropic import Anthropic

# ----------------------------------------------------------------------
# Known-legitimate SDK/library package prefixes. Anything bundled in the
# APK that ISN'T in this allowlist and isn't the app's own package is
# flagged as "unknown third-party code" for lineage review.
# ----------------------------------------------------------------------
KNOWN_SDK_PREFIXES = [
    "com.google.android", "com.google.firebase", "com.google.gson",
    "com.google.android.gms", "com.facebook", "com.squareup.okhttp",
    "com.squareup.retrofit", "com.bumptech.glide", "androidx.",
    "android.support", "kotlin.", "kotlinx.", "okio.", "com.airbnb.lottie",
    "io.reactivex", "com.jakewharton", "org.greenrobot", "com.razorpay",
    "com.paytm", "com.google.android.material",
]

# Markers that suggest the APK was rebuilt/re-signed by a common
# repackaging or cracking toolchain rather than compiled by the original
# developer's build system.
REPACKAGE_TOOL_CLASS_MARKERS = [
    "com/lody/virtual", "com/apkprotect", "com/tencent/StubShell",
    "com/secneo/apkwrapper", "org/anddev", "com/blankj/utilcode",
]


class G6LineageAnalyzer:
    def __init__(self, extractor, anthropic_api_key: str = None, use_llm: bool = True,
                 reference_extractor=None):
        """
        reference_extractor: optional second APKExtractor instance pointing
        at a KNOWN-LEGITIMATE version of the app (e.g. downloaded fresh from
        the Play Store) to compare structural similarity against.
        """
        self.extractor = extractor
        self.reference_extractor = reference_extractor
        self.use_llm = use_llm
        self.client = Anthropic(api_key=anthropic_api_key) if use_llm else None

    # --------------------------------------------------------------
    def analyze(self) -> dict:
        cert = self.extractor.get_certificate_details()
        top_packages = self.extractor.get_top_level_packages()
        repackage_markers = self.extractor.has_repackaging_markers()
        file_hash = self.extractor.get_file_hash()
        app_label, package_name = self.extractor.get_app_label_and_package()

        unknown_libs = self._classify_libraries(top_packages)
        suspicious_class_markers = self._find_repackage_tool_markers(top_packages)

        similarity_result = None
        if self.reference_extractor is not None:
            similarity_result = self._compare_to_reference()

        rule_score = self._rule_based_score(
            cert, unknown_libs, suspicious_class_markers, repackage_markers, similarity_result
        )

        llm_result = {"score": rule_score, "narrative": ""}
        if self.use_llm:
            llm_result = self._llm_reasoning(
                app_label, package_name, cert, unknown_libs,
                suspicious_class_markers, repackage_markers, similarity_result
            )

        final_score = round(0.4 * rule_score + 0.6 * llm_result["score"])
        final_score = max(0, min(100, final_score))

        evidence = self._build_evidence(
            cert, unknown_libs, suspicious_class_markers, repackage_markers,
            similarity_result, llm_result
        )

        return {
            "strand": "G6",
            "score": final_score,
            "evidence": evidence,
            "raw_features": {
                "package_name": package_name,
                "app_label": app_label,
                "file_sha256": file_hash,
                "certificate": cert,
                "total_bundled_libraries": len(top_packages),
                "unknown_unclassified_libraries": unknown_libs[:15],
                "repackage_tool_markers": suspicious_class_markers,
                "repackage_file_artifacts": repackage_markers,
                "reference_comparison": similarity_result,
                "llm_narrative": llm_result.get("narrative", ""),
            }
        }

    # --------------------------------------------------------------
    def _classify_libraries(self, top_packages):
        """Returns list of top-level package prefixes NOT matched against
        the known-SDK allowlist — i.e. unclassified/unknown bundled code."""
        unknown = []
        for pkg, class_count in sorted(top_packages.items(), key=lambda x: -x[1]):
            if not any(pkg.startswith(k) for k in KNOWN_SDK_PREFIXES):
                unknown.append({"package": pkg, "class_count": class_count})
        return unknown

    def _find_repackage_tool_markers(self, top_packages):
        found = []
        for pkg in top_packages:
            for marker in REPACKAGE_TOOL_CLASS_MARKERS:
                if marker.replace("/", ".") in pkg:
                    found.append(pkg)
        return found

    # --------------------------------------------------------------
    def _compare_to_reference(self):
        """Jaccard similarity of class-name sets between the submitted APK
        and a known-legitimate reference APK, plus a cert fingerprint check.
        High code similarity + mismatched cert = classic repackaging pattern."""
        target_classes = self.extractor.get_all_class_names()
        ref_classes = self.reference_extractor.get_all_class_names()

        if not target_classes or not ref_classes:
            return None

        intersection = target_classes & ref_classes
        union = target_classes | ref_classes
        jaccard = len(intersection) / len(union) if union else 0.0

        target_cert = self.extractor.get_certificate_details()["fingerprint_sha256"]
        ref_cert = self.reference_extractor.get_certificate_details()["fingerprint_sha256"]

        return {
            "class_structure_similarity": round(jaccard, 3),
            "shared_class_count": len(intersection),
            "target_cert_fingerprint": target_cert,
            "reference_cert_fingerprint": ref_cert,
            "cert_matches_reference": target_cert == ref_cert if (target_cert and ref_cert) else None,
        }

    # --------------------------------------------------------------
    def _rule_based_score(self, cert, unknown_libs, suspicious_markers, repackage_markers, similarity_result):
        score = 0

        if cert.get("is_self_signed"):
            score += 10  # normal for many apps, mild signal alone

        score += min(len(unknown_libs), 10) * 2
        score += min(len(suspicious_markers), 3) * 15
        score += min(len(repackage_markers), 3) * 10

        if similarity_result:
            sim = similarity_result["class_structure_similarity"]
            cert_match = similarity_result["cert_matches_reference"]
            if sim > 0.75 and cert_match is False:
                score += 40  # strong repackaging signal: same code, different signer
            elif sim > 0.5 and cert_match is False:
                score += 20

        return min(100, score)

    # --------------------------------------------------------------
    def _llm_reasoning(self, app_label, package_name, cert, unknown_libs,
                        suspicious_markers, repackage_markers, similarity_result):
        prompt = f"""You are the Lineage Tracer agent in a banking-malware detection pipeline,
responsible for supply-chain provenance analysis of Android APKs.

App label: {app_label}
Package name: {package_name}
Certificate self-signed: {cert.get('is_self_signed')}
Certificate issuer: {cert.get('issuer')}

Unrecognized/unclassified bundled libraries (top-level packages not matching known SDKs):
{json.dumps(unknown_libs[:10], indent=2)}

Known repackaging-tool class markers found: {suspicious_markers}
Repackaging file artifacts found (e.g. apktool.yml): {repackage_markers}

Reference-app structural comparison (if available): {json.dumps(similarity_result, indent=2)}

Task: Based on this evidence, assess whether this APK is likely:
(a) an original, legitimately built app,
(b) a repackaged/trojanized clone of a legitimate app with malicious code injected, or
(c) inconclusive from available signals.

Rate 0-100 how strongly the evidence points to (b) — a trojanized supply-chain compromise.
Write a short 1-2 sentence provenance narrative explaining your reasoning.

Respond with ONLY valid JSON, no preamble, no markdown fences:
{{"score": <int 0-100>, "narrative": "<1-2 sentence explanation>"}}"""

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(block.text for block in response.content if block.type == "text")
            text = re.sub(r"```json|```", "", text).strip()
            parsed = json.loads(text)
            parsed["score"] = max(0, min(100, int(parsed.get("score", 0))))
            return parsed
        except Exception as e:
            return {"score": 0, "narrative": "", "error": str(e)}

    # --------------------------------------------------------------
    def _build_evidence(self, cert, unknown_libs, suspicious_markers, repackage_markers,
                         similarity_result, llm_result):
        evidence = []

        if similarity_result:
            sim = similarity_result["class_structure_similarity"]
            cert_match = similarity_result["cert_matches_reference"]
            if sim > 0.5 and cert_match is False:
                evidence.append(
                    f"Supply chain lineage confirms {int(sim*100)}% code structure match to "
                    f"reference app but signing certificate differs — repackaged/trojanized variant"
                )

        if suspicious_markers:
            evidence.append(f"Repackaging tool signatures detected in bundled code: {suspicious_markers[:2]}")

        if repackage_markers:
            evidence.append(f"APK rebuild artifacts found (e.g. apktool metadata): {repackage_markers[:2]}")

        if llm_result.get("narrative"):
            evidence.append(llm_result["narrative"])

        if unknown_libs and len(unknown_libs) > 5:
            evidence.append(f"{len(unknown_libs)} unclassified third-party libraries bundled — unusually high")

        if not evidence:
            evidence.append("No supply-chain tampering or repackaging signals detected")

        return evidence[:6]


if __name__ == "__main__":
    import sys
    from apk_extractor import APKExtractor

    if len(sys.argv) < 2:
        print("Usage: python g6_lineage.py <path_to_apk> [anthropic_api_key] [--reference path_to_legit_apk]")
        sys.exit(1)

    apk_path = sys.argv[1]
    api_key = None
    reference_path = None

    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--reference" and i + 1 < len(args):
            reference_path = args[i + 1]
            i += 2
        else:
            api_key = args[i]
            i += 1

    extractor = APKExtractor(apk_path)
    ref_extractor = APKExtractor(reference_path) if reference_path else None

    analyzer = G6LineageAnalyzer(
        extractor, anthropic_api_key=api_key, use_llm=bool(api_key),
        reference_extractor=ref_extractor
    )
    result = analyzer.analyze()
    print(json.dumps(result, indent=2))
