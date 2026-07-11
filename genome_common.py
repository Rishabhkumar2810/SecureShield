"""
genome_common.py
-----------------
Shared helpers for SecureStrand AI genome-strand modules (G3, G5, ...).

Provides:
  - build_strand_output(): assembles the canonical output dict/JSON
  - clamp_score(): keeps composite scores in [0, 100]
  - safe_load_apk(): consistent androguard APK/DEX/Analysis loader with error handling
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from androguard.misc import AnalyzeAPK


def clamp_score(score: float) -> int:
    """Clamp a raw score to the 0-100 integer range expected by the schema."""
    return max(0, min(100, round(score)))


def build_strand_output(
    strand: str,
    score: float,
    evidence: List[str],
    raw_features: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Assemble output in the exact schema used across all SSA genome strands:

    {
      "strand": "G3",
      "score": 0-100,
      "evidence": ["...", "..."],
      "raw_features": {...}
    }
    """
    return {
        "strand": strand,
        "score": clamp_score(score),
        "evidence": evidence,
        "raw_features": raw_features,
    }


@dataclass
class LoadedAPK:
    apk: Any
    dvm_list: Any
    analysis: Any
    path: str
    error: str = None


def safe_load_apk(apk_path: str) -> LoadedAPK:
    """
    Load an APK once via androguard's AnalyzeAPK, which gives you:
      - apk: the APK object (manifest, permissions, resources, raw strings.xml)
      - dvm_list: list of DalvikVMFormat objects (one per DEX file, multidex-safe)
      - analysis: the cross-referenced Analysis object (call graph, xrefs, methods)

    This is intentionally the ONE place both G3 and G5 touch the APK, so a
    pipeline running all 6 genome strands only decompiles/parses once and
    hands the same LoadedAPK to every strand agent (mirrors A-01 DecompilerSage
    -> A-02 GenomeSplicer -> A-03..A-08 in the doc's architecture).
    """
    try:
        apk, dvm_list, analysis = AnalyzeAPK(apk_path)
        return LoadedAPK(apk=apk, dvm_list=dvm_list, analysis=analysis, path=apk_path)
    except Exception as e:
        return LoadedAPK(apk=None, dvm_list=None, analysis=None, path=apk_path, error=str(e))


def to_json(result: Dict[str, Any], indent: int = 2) -> str:
    return json.dumps(result, indent=indent, ensure_ascii=False)
