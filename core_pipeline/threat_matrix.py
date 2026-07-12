import json

class RiskComposerA11:
    """Implements the SecureStrand AI Phase 1 Dynamic Risk Matrix Engine (Agent A-11)."""
    
    @staticmethod
    def calculate_phantom_score(g1_payload: dict, g4_payload: dict) -> dict:
        g1_raw = g1_payload.get("score", 0) / 100.0
        g4_raw = g4_payload.get("score", 0) / 100.0
        
        # G1 Evaluation logic & Banking Boost
        g1_weight = 0.20
        api_calls = g1_payload.get("raw_features", {}).get("api_calls", [])
        has_g1_boost = any("com.secure.banking" in api or "AccessibilityService" in api for api in api_calls)
        if has_g1_boost:
            g1_weight += 0.08
        g1_contribution = min(g1_raw * g1_weight * 100, 28)
        
        # G4 Evaluation logic & Banking Boost
        g4_weight = 0.18
        urls = g4_payload.get("raw_features", {}).get("extracted_urls", [])
        if len(urls) > 0:
            g4_weight += 0.05
        g4_contribution = min(g4_raw * g4_weight * 100, 23)
        
        # Scaling math
        current_max_possible = 28 + 23
        phantom_score = int(((g1_contribution + g4_contribution) / current_max_possible) * 100)
        
        if phantom_score >= 75:
            threat_band = "CRITICAL THREAT"
        elif phantom_score >= 40:
            threat_band = "SUSPICIOUS / ELEVATED RISK"
        else:
            threat_band = "LOW RISK"
            
        # Assemble Explainability Traces
        narrative_summary = []
        if g1_contribution > 0:
            narrative_summary.append(g1_payload.get("reasoning_trace"))
        if g4_contribution > 0:
            narrative_summary.append(g4_payload.get("reasoning_trace"))
            
        return {
            "phantom_score": f"{phantom_score}/100",
            "threat_band": threat_band,
            "forensic_narrative": " | ".join(narrative_summary) if narrative_summary else "Application exhibits standard clean operational telemetry.",
            "metrics_evaluated": {
                "g1_semantic_points": round(g1_contribution, 2),
                "g4_network_points": round(g4_contribution, 2)
            }
        }
