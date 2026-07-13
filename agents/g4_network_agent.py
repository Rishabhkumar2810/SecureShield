import json
from strands.g4_network.extractor import G4NetworkExtractor

class G4NetworkAgent:
    def analyze(self, raw_strings: list) -> dict:
        extractor = G4NetworkExtractor(raw_strings)
        features = extractor.extract_features()
        
        url_count = len(features.get("extracted_urls", []))
        ip_count = len(features.get("extracted_ips", []))
        score = min((url_count + ip_count) * 35, 100)
        
        evidence = []
        if url_count > 0 or ip_count > 0:
            evidence.append(f"Identified {url_count} cleartext endpoints and {ip_count} target IPs hardcoded in binary.")
        else:
            evidence.append("Network profile analysis clean. No suspicious active connection channels found.")
            
        return {
            "strand": "G4",
            "score": score,
            "evidence": evidence,
            "raw_features": features
        }
