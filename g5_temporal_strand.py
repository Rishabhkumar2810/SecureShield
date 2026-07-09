"""
g5_temporal_strand.py
-----------------------
G5 - Temporal Execution Rhythm Strand

Captures: trigger conditions, time-bombs, sleeper activation logic.
AI techniques (target state): symbolic execution + LLM code-path reasoning.

This module implements a working v1: static call-graph heuristics that
approximate symbolic execution by checking whether a "trigger source"
(time/counter/environment API) reaches a "sensitive sink" (SMS, contacts,
overlay, network) within a bounded number of call-graph hops. This is far
cheaper than full symbolic execution and catches the large majority of
real-world sleeper-trojan patterns; the doc's full symbolic executor is a
Phase-2/3 upgrade noted at the bottom of this file.

Corresponds to Agent A-07 "Chrono Bomb Detector" in the SSA architecture.
"""

from collections import defaultdict
from typing import Dict, List, Set, Tuple

from genome_common import LoadedAPK, build_strand_output, safe_load_apk, to_json

# ---------------------------------------------------------------------------
# 1. TRIGGER-SOURCE APIs
#    Calls that introduce a time-, counter-, or environment-gated condition.
#    Weighted by how strongly each correlates with deliberate delay/evasion
#    vs. legitimate everyday use (e.g. currentTimeMillis is very common and
#    low-signal alone; AlarmManager.setExact + BOOT_COMPLETED together is
#    high-signal persistence+scheduling).
# ---------------------------------------------------------------------------

TRIGGER_SOURCES: Dict[str, float] = {
    "Landroid/app/AlarmManager;->setExact": 3.0,
    "Landroid/app/AlarmManager;->setRepeating": 2.5,
    "Landroid/app/AlarmManager;->set": 2.0,
    "Landroid/app/job/JobScheduler;->schedule": 2.5,
    "Landroidx/work/WorkManager;": 2.0,
    "Ljava/lang/Thread;->sleep": 1.5,
    "Landroid/os/SystemClock;->elapsedRealtime": 0.8,
    "Ljava/lang/System;->currentTimeMillis": 0.6,
    "Ljava/util/Calendar;": 1.0,
    "Ljava/util/Date;": 0.8,
    "Landroid/os/Debug;->isDebuggerConnected": 2.0,   # anti-analysis
    "Landroid/os/Build;->FINGERPRINT": 1.5,            # emulator detection
    "Landroid/content/SharedPreferences;->getInt": 0.5,  # often used for launch counters
}

# BOOT_COMPLETED receiver = persistence across reboot, a precondition for
# most sleeper-trojan patterns. Checked separately via the manifest.
PERSISTENCE_RECEIVER = "android.intent.action.BOOT_COMPLETED"

# ---------------------------------------------------------------------------
# 2. SENSITIVE SINK APIs
#    What the trigger is "arming" -- if a time-gate feeds one of these,
#    that's the payload the sleeper logic is protecting.
# ---------------------------------------------------------------------------

SENSITIVE_SINKS: Dict[str, float] = {
    "Landroid/telephony/SmsManager;->sendTextMessage": 4.0,
    "Landroid/content/ContentResolver;->query": 1.5,        # contacts/SMS DB read
    "Landroid/view/WindowManager;->addView": 3.0,            # overlay attack surface
    "Ljava/net/HttpURLConnection;": 1.5,
    "Lokhttp3/": 1.0,
    "Landroid/accessibilityservice/AccessibilityService;": 3.5,
    "Landroid/app/admin/DevicePolicyManager;": 3.0,          # device-admin abuse
}

MAX_CALL_GRAPH_HOPS = 2  # how far downstream from a trigger we look for a sink


# ---------------------------------------------------------------------------
# 3. METHOD-LEVEL SCAN
#    For every method body, record which trigger-source and sink constants
#    it references (via instruction operands / xrefs).
# ---------------------------------------------------------------------------

def _method_key(method_analysis) -> str:
    m = method_analysis.get_method()
    return f"{m.get_class_name()}->{m.get_name()}{m.get_descriptor()}"


def build_method_index(loaded: LoadedAPK) -> Dict[str, object]:
    """
    method_key -> MethodAnalysis, built once. MethodAnalysis (from
    analysis.get_methods()) is the object that carries BOTH the real
    EncodedMethod (via .get_method(), which has .get_code() for bytecode)
    AND the call-graph edges (via .get_xref_to()/.get_xref_from()) -- the
    raw dvm.get_methods() list only gives MethodIdItem stubs with no code.
    """
    index = {}
    for ma in loaded.analysis.get_methods():
        try:
            index[_method_key(ma)] = ma
        except Exception:
            continue
    return index


def scan_methods_for_apis(loaded: LoadedAPK, method_index: Dict) -> Tuple[Dict, Dict]:
    """
    Returns:
      method_triggers: {method_key: [(api_substr, weight), ...]}
      method_sinks:    {method_key: [(api_substr, weight), ...]}
    """
    method_triggers = defaultdict(list)
    method_sinks = defaultdict(list)

    for key, ma in method_index.items():
        try:
            em = ma.get_method()
            code = em.get_code()
            if not code:
                continue
            bc = code.get_bc()
            for ins in bc.get_instructions():
                output = ins.get_output() if hasattr(ins, "get_output") else ""
                if not output:
                    continue
                for api, weight in TRIGGER_SOURCES.items():
                    if api in output:
                        method_triggers[key].append((api, weight))
                for api, weight in SENSITIVE_SINKS.items():
                    if api in output:
                        method_sinks[key].append((api, weight))
        except Exception:
            continue

    return dict(method_triggers), dict(method_sinks)


# ---------------------------------------------------------------------------
# 4. CALL-GRAPH PROXIMITY CHECK
#    Approximates "does this trigger gate this sink" without full symbolic
#    execution: same-method co-occurrence is strongest signal; caller/callee
#    proximity within MAX_CALL_GRAPH_HOPS is weaker but still meaningful.
# ---------------------------------------------------------------------------

def get_callees(method_index: Dict, method_key: str) -> Set[str]:
    """
    O(1) lookup via the pre-built method_index, instead of re-scanning every
    method in the DEX on every call (which is what made the original
    per-call full-VM search unusably slow on anything but a toy APK).
    get_xref_to() on a MethodAnalysis yields (class_analysis, method_analysis,
    offset) triples for everything this method calls.
    """
    callees = set()
    ma = method_index.get(method_key)
    if ma is None:
        return callees
    try:
        for _, callee_ma, _ in ma.get_xref_to():
            try:
                callees.add(_method_key(callee_ma))
            except Exception:
                continue
    except Exception:
        pass
    return callees


def find_trigger_sink_pairs(
    method_index: Dict, method_triggers: Dict, method_sinks: Dict
) -> List[Dict]:
    pairs = []

    # Same-method co-occurrence (strongest signal: the gate and the payload
    # sit in one function, e.g. `if (currentTimeMillis - installTime > X) sendSms(...)`)
    for method_key in method_triggers:
        if method_key in method_sinks:
            for t_api, t_w in method_triggers[method_key]:
                for s_api, s_w in method_sinks[method_key]:
                    pairs.append(
                        {
                            "method": method_key,
                            "trigger": t_api,
                            "sink": s_api,
                            "hops": 0,
                            "confidence_weight": t_w * s_w,
                        }
                    )

    # Cross-method (N-hop) co-occurrence via call graph
    for method_key in method_triggers:
        if method_key in method_sinks:
            continue  # already captured above
        visited = {method_key}
        frontier = {method_key}
        for hop in range(1, MAX_CALL_GRAPH_HOPS + 1):
            next_frontier = set()
            for m in frontier:
                for callee in get_callees(method_index, m):
                    if callee in visited:
                        continue
                    visited.add(callee)
                    if callee in method_sinks:
                        for t_api, t_w in method_triggers[method_key]:
                            for s_api, s_w in method_sinks[callee]:
                                pairs.append(
                                    {
                                        "method": f"{method_key} -> {callee}",
                                        "trigger": t_api,
                                        "sink": s_api,
                                        "hops": hop,
                                        "confidence_weight": (t_w * s_w) / (hop + 1),
                                    }
                                )
                    next_frontier.add(callee)
            frontier = next_frontier

    return pairs


# ---------------------------------------------------------------------------
# 5. PERSISTENCE CHECK (BOOT_COMPLETED)
# ---------------------------------------------------------------------------

def has_boot_persistence(loaded: LoadedAPK) -> bool:
    try:
        receivers_xml = loaded.apk.get_android_manifest_xml()
        manifest_str = receivers_xml.toxml() if receivers_xml is not None else ""
        return PERSISTENCE_RECEIVER in manifest_str
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 6. STRAND ENTRY POINT
# ---------------------------------------------------------------------------

def analyze_g5(apk_path: str) -> Dict:
    loaded = safe_load_apk(apk_path)
    if loaded.error:
        return build_strand_output(
            strand="G5",
            score=0,
            evidence=[f"ERROR loading APK: {loaded.error}"],
            raw_features={"load_error": loaded.error},
        )

    method_index = build_method_index(loaded)
    method_triggers, method_sinks = scan_methods_for_apis(loaded, method_index)
    pairs = find_trigger_sink_pairs(method_index, method_triggers, method_sinks)
    boot_persist = has_boot_persistence(loaded)

    raw_score = sum(p["confidence_weight"] for p in pairs)
    if boot_persist and pairs:
        raw_score *= 1.4  # persistence + trigger-sink pair together = sleeper trojan pattern
        boot_note = "BOOT_COMPLETED receiver present alongside trigger logic (persistence + delayed activation)"
    elif boot_persist:
        raw_score += 1.0
        boot_note = "BOOT_COMPLETED receiver present (persistence only, no trigger->sink pair found)"
    else:
        boot_note = "No BOOT_COMPLETED persistence receiver found"

    normalized_score = min(100, raw_score * 3.0)

    evidence = [boot_note]
    # surface the strongest pairs first, cap evidence list length for readability
    for p in sorted(pairs, key=lambda x: -x["confidence_weight"])[:8]:
        evidence.append(
            f'trigger "{p["trigger"]}" reaches sink "{p["sink"]}" '
            f'({p["hops"]} call-hop{"s" if p["hops"] != 1 else ""}) in {p["method"]}'
        )
    if not pairs:
        evidence.append("No trigger-source to sensitive-sink paths detected within call-graph search depth.")

    raw_features = {
        "methods_with_trigger_apis": len(method_triggers),
        "methods_with_sink_apis": len(method_sinks),
        "trigger_sink_pairs_found": len(pairs),
        "boot_persistence_receiver": boot_persist,
        "raw_weighted_score": round(raw_score, 2),
        "max_call_graph_hops_searched": MAX_CALL_GRAPH_HOPS,
    }

    return build_strand_output("G5", normalized_score, evidence, raw_features)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python g5_temporal_strand.py <path_to_apk>")
        sys.exit(1)
    result = analyze_g5(sys.argv[1])
    print(to_json(result))


# ---------------------------------------------------------------------------
# UPGRADE PATH: full symbolic execution (matches doc section 4 exactly)
# ---------------------------------------------------------------------------
# The heuristic above answers "can a trigger reach a sink at all". True
# symbolic execution additionally solves the PATH CONDITION -- e.g. proving
# the branch requires `(currentTime - installTime) > 259200000` (72 hours),
# which is what lets you generate the doc's narrative line "sleeper trigger
# activating 72 hours post-install." To get there:
#   1. Convert each method's Dalvik bytecode to an IR (androguard's
#      `analysis.get_method(m).get_basic_blocks()` gives you the CFG).
#   2. Walk the CFG with a symbolic state (a Z3 solver context), assigning
#      symbolic values to trigger-source return values.
#   3. At each conditional branch (if-eq/if-lt/etc.) that depends on a
#      symbolic trigger value, add the branch condition as a Z3 constraint
#      and check satisfiability down the path that reaches the sink.
#   4. If satisfiable, ask Z3 for a model -- the concrete constraint value
#      (e.g. 259200000 ms) is your extracted trigger threshold, which you
#      then hand to an LLM purely for natural-language phrasing
#      ("activates 72 hours post-install") -- the LLM is NOT solving the
#      logic, just narrating a value Z3 already proved.
# Libraries: `z3-solver` (pip installable) for the constraint solving.
