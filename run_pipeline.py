import json
from agents.g1_semantic_agent import G1SemanticAgent
from agents.g4_network_agent import G4NetworkAgent
from core_pipeline.threat_matrix import RiskComposerA11

def main():
    print("[*] Initializing SecureStrand AI (Swarm Phase 1 Ensembles)...")
    
    # Instantiate the active agents
    g1_agent = G1SemanticAgent()
    g4_agent = G4NetworkAgent()
    
    # Simulated data input extracted via AST parsing structures
    mock_structural_nodes = [{"class": "com.secure.banking.SmsReceiver", "methods": ["onReceive"]}]
    mock_strings = ["http://covert-c2-tracker.xyz/api/v1/collect"]
    
    print("\n[*] Running Agent A-03 (Semantic Oracle)...")
    g1_result = g1_agent.analyze(mock_structural_nodes)
    
    print("[*] Running Agent A-06 (Net Shadow)...")
    g4_result = g4_agent.analyze(mock_strings)
    
    print("\n[*] Invoking Agent A-11 (Risk Composer Matrix Assembly)...")
    composite_report = RiskComposerA11.calculate_phantom_score(g1_result, g4_result)
    
    print("\n================ SECURESTRAND AI ASSESSMENT ================")
    print(json.dumps(composite_report, indent=2))
    print("============================================================")

if __name__ == "__main__":
    main()
