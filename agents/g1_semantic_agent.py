import json
from strands.g1_semantic.extractor import G1SemanticExtractor

class G1SemanticAgent:
    def analyze(self, structural_nodes: list) -> dict:
        extractor = G1SemanticExtractor(structural_nodes)
        features = extractor.extract_features()
        
        # Calculate dynamic risk score locally based on API counts
        api_count = len(features.get("api_calls", []))
        score = min(api_count * 25, 100) 
        
        evidence = []
        if api_count > 0:
            evidence.append(f"Flagged {api_count} dangerous semantic method hooks directly inside class declarations.")
        else:
            evidence.append("No high-risk structural semantic API matches detected inside DEX tracking arrays.")
            
        return {
            "strand": "G1",
            "score": score,
            "evidence": evidence,
            "raw_features": features
        }
