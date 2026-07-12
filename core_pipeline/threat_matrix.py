import json

class RiskComposerA11:
    """Implements the SecureStrand AI Phase 1 Dynamic Risk Matrix Engine (Agent A-11)."""
    
    @staticmethod
    def calculate_phantom_score(g1_payload: dict, g4_payload: dict) -> dict:
        # Base Raw Risk Inputs normalized from the individual agents (0.0 to 1.0)
        g1_raw = g1_payload.get("score", 0) / 100.0
        g4_raw = g4_payload.get("score", 0) / 100.0
        
        # 1. Evaluate G1 Semantic Opcode Strand (Base Weight: 20%, Max Contribution: 28 pts)
        g1_weight = 0.20
        # Check raw features for high-risk banking API patterns
        api_calls = g1_payload.get("raw_features", {}).get("api_calls", [])
        if any("com.secure.banking" in api for api in api_calls):
            g1_weight += 0.08  # Apply Banking Boost (+8%)
            
        g1_contribution = min(g1_raw * g1_weight * 100, 28)
        
        # 2. Evaluate G4 Network Behavior Helix (Base Weight: 18%, Max Contribution: 23 pts)
        g4_weight = 0.18
        # Check raw features for active cleartext endpoints
        urls = g4_payload.get("raw_features", {}).get("extracted_urls", [])
        if len(urls) > 0:
            g4_weight += 0.05  # Apply Banking Boost (+5%)
            
        g4_contribution = min(g4_raw * g4_weight * 100, 23)
        
        # Phase 1 Aggregation Strategy (Scaled to a clean 0-100 score for current active strands)
        current_max_possible = 28 + 23
        raw_combined = g1_contribution + g4_contribution
        
        # Final scaled mathematical calculation
        phantom_score = int((raw_combined / current_max_possible) * 100)
        
        # Determine enterprise threat level classification
        if phantom_score >= 75:
            threat_band = "CRITICAL THREAT"
        elif phantom_score >= 40:
            threat_band = "SUSPICIOUS / ELEVATED RISK"
        else:
            threat_band = "LOW RISK"
            
        return {
            "phantom_score": f"{phantom_score}/100",
            "threat_band": threat_band,
            "metrics_evaluated": {
                "g1_semantic_points": round(g1_contribution, 2),
                "g4_network_points": round(g4_contribution, 2)
            }
        }
