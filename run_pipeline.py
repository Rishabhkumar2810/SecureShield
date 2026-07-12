import json
from core_pipeline.decompiler_sage import DecompilerSageA01
from agents.g1_semantic_agent import G1SemanticAgent
from agents.g4_network_agent import G4NetworkAgent
from core_pipeline.threat_matrix import RiskComposerA11

def main():
    print("[*] Initializing SecureStrand AI (Swarm Phase 1 Ensembles)...")
    
    target_file = "target_app_code.txt"
    
    # 1. Run the upgraded Ingestion Engine
    extracted_data = DecompilerSageA01.extract_features_from_file(target_file)
    
    # 2. Re-route real extracted features dynamically into the agents
    # Instead of raw mock values, we construct structural elements from the actual file lines
    structural_nodes = []
    for api in extracted_data["api_calls"]:
        structural_nodes.append({"class": api, "methods": ["triggered"]})
        
    network_strings = extracted_data["extracted_urls"]
    
    # 3. Instantiate Agents
    g1_agent = G1SemanticAgent()
    g4_agent = G4NetworkAgent()
    
    print("\n[*] Running Agent A-03 (Semantic Oracle)...")
    g1_result = g1_agent.analyze(structural_nodes)
    
    print("[*] Running Agent A-06 (Net Shadow)...")
    g4_result = g4_agent.analyze(network_strings)
    
    # Dynamically scale agent score matrices based on raw count of dangerous indicators found
    if len(extracted_data["api_calls"]) > 0:
        # Scale score up dynamically: 40 points per unique malicious API pattern found (Cap at 100)
        g1_result["score"] = min(len(extracted_data["api_calls"]) * 45, 100)
        g1_result["raw_features"] = {"api_calls": extracted_data["api_calls"]}
        
    if len(network_strings) > 0:
        # Scale score up dynamically: 45 points per suspicious URL type found (Cap at 100)
        g4_result["score"] = min(len(network_strings) * 45, 100)
        g4_result["raw_features"] = {"extracted_urls": network_strings}
    
    print("\n[*] Invoking Agent A-11 (Risk Composer Matrix Assembly)...")
    composite_report = RiskComposerA11.calculate_phantom_score(g1_result, g4_result)
    
    print("\n================ SECURESTRAND AI ASSESSMENT ================")
    print(json.dumps(composite_report, indent=2))
    print("============================================================")

if __name__ == "__main__":
    main()
