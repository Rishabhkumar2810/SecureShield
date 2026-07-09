"""
run_analysis.py
-----------------
Entry point: give it an APK, get back G3 + G5 strand results in the
standard SecureStrand AI schema.

Usage:
    python run_analysis.py path/to/app.apk
    python run_analysis.py path/to/app.apk --api-key sk-ant-...
    python run_analysis.py path/to/app.apk --no-llm   # rule-based only, no API cost

Or set the ANTHROPIC_API_KEY environment variable instead of --api-key.
"""

import argparse
import json
import os
import sys

from apk_extractor import APKExtractor
from g1_semantic import G1SemanticAnalyzer
from g2_permission import G2PermissionAnalyzer
from g3_linguistic import G3LinguisticAnalyzer
from g4_network import G4NetworkAnalyzer
from g5_temporal import G5TemporalAnalyzer
from g6_lineage import G6LineageAnalyzer


def main():
    parser = argparse.ArgumentParser(description="Run G1+G2+G3+G4+G5+G6 SecureStrand AI analysis on an APK")
    parser.add_argument("apk_path", help="Path to the .apk file to analyze")
    parser.add_argument("--api-key", default=os.environ.get("ANTHROPIC_API_KEY"),
                         help="Anthropic API key (or set ANTHROPIC_API_KEY env var)")
    parser.add_argument("--no-llm", action="store_true",
                         help="Skip LLM reasoning layer, use only rule-based scoring")
    parser.add_argument("--reference", default=None,
                         help="Optional path to a known-legitimate reference APK, used by G6 "
                              "to detect repackaging via structural similarity")
    parser.add_argument("--out", default=None, help="Optional path to write combined JSON output")
    args = parser.parse_args()

    if not os.path.exists(args.apk_path):
        print(f"ERROR: file not found: {args.apk_path}")
        sys.exit(1)

    use_llm = not args.no_llm
    if use_llm and not args.api_key:
        print("WARNING: no Anthropic API key provided — falling back to rule-based scoring only.")
        print("         (pass --api-key or set ANTHROPIC_API_KEY to enable the LLM reasoning layer)\n")
        use_llm = False

    print(f"[1/7] Decompiling & extracting: {args.apk_path} ...")
    extractor = APKExtractor(args.apk_path)

    reference_extractor = None
    if args.reference:
        print(f"      Also decompiling reference APK: {args.reference} ...")
        reference_extractor = APKExtractor(args.reference)

    print("[2/7] Running G1 — Semantic Opcode Chromosome Strand ...")
    g1 = G1SemanticAnalyzer(extractor, anthropic_api_key=args.api_key, use_llm=use_llm)
    g1_result = g1.analyze()

    print("[3/7] Running G2 — Permission Intent Graph Strand ...")
    g2 = G2PermissionAnalyzer(extractor, anthropic_api_key=args.api_key, use_llm=use_llm)
    g2_result = g2.analyze()

    print("[4/7] Running G3 — Linguistic Social Engineering Strand ...")
    g3 = G3LinguisticAnalyzer(extractor, anthropic_api_key=args.api_key, use_llm=use_llm)
    g3_result = g3.analyze()

    print("[5/7] Running G4 — Network Behavior Helix Strand ...")
    g4 = G4NetworkAnalyzer(extractor, anthropic_api_key=args.api_key, use_llm=use_llm)
    g4_result = g4.analyze()

    print("[6/7] Running G5 — Temporal Execution Rhythm Strand ...")
    g5 = G5TemporalAnalyzer(extractor, anthropic_api_key=args.api_key, use_llm=use_llm)
    g5_result = g5.analyze()

    print("[7/7] Running G6 — Supply Chain Lineage Strand ...")
    g6 = G6LineageAnalyzer(extractor, anthropic_api_key=args.api_key, use_llm=use_llm,
                            reference_extractor=reference_extractor)
    g6_result = g6.analyze()

    combined = {
        "apk_path": args.apk_path,
        "strands": [g1_result, g2_result, g3_result, g4_result, g5_result, g6_result],
    }

    output_json = json.dumps(combined, indent=2)
    print("\n" + "=" * 60)
    print(output_json)

    if args.out:
        with open(args.out, "w") as f:
            f.write(output_json)
        print(f"\nSaved combined output to: {args.out}")


if __name__ == "__main__":
    main()
