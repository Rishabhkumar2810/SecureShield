import json
from agents.g1_semantic_agent import G1SemanticAgent
from agents.g4_network_agent import G4NetworkAgent

def test_local_pipeline():
    print("[*] Initializing G1 and G4 Agents...")
    g1_agent = G1SemanticAgent()
    g4_agent = G4NetworkAgent()
    
    # Simulated mock data that mimics what your core_pipeline will eventually pass down
    fake_structural_nodes = [
        {"class": "com.secure.banking.SmsReceiver", "method": "onReceive", "descriptor": "Landroid/telephony/SmsManager;->sendTextMessage"}
    ]
    fake_raw_strings = [
        "Connecting to secure channel: http://covert-c2-tracker.xyz/api/v1/collect",
        "Executing backup routine via dns_lookup"
    ]
    
    # Run the agents locally
    print("\n[*] Running G1 (Semantic Opcode) Agent...")
    g1_result = g1_agent.analyze(fake_structural_nodes)
    print(json.dumps(g1_result, indent=2))
    
    print("\n[*] Running G4 (Network Behavior) Agent...")
    g4_result = g4_agent.analyze(fake_raw_strings)
    print(json.dumps(g4_result, indent=2))

if __name__ == "__main__":
    test_local_pipeline()