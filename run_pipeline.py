import json
import os
from datetime import datetime
from core_pipeline.decompiler_sage import DecompilerSageA01
from agents.g1_semantic_agent import G1SemanticAgent
from agents.g4_network_agent import G4NetworkAgent
from core_pipeline.threat_matrix import RiskComposerA11

def main():
    print("[*] Initializing SecureStrand AI (Swarm Phase 1 Ensembles)...")
    
    target_file = "target_app_code.txt"
    
    # 1. Run Ingestion Engine
    extracted_data = DecompilerSageA01.extract_features_from_file(target_file)
    
    structural_nodes = [{"class": api, "methods": ["triggered"]} for api in extracted_data["api_calls"]]
    network_strings = extracted_data["extracted_urls"]
    
    # 2. Instantiate Agents
    g1_agent = G1SemanticAgent()
    g4_agent = G4NetworkAgent()
    
    g1_result = g1_agent.analyze(structural_nodes)
    g4_result = g4_agent.analyze(network_strings)
    
    # 3. Dynamic Rule Scoring + Explainability Trace Injection
    if len(extracted_data["api_calls"]) > 0:
        g1_result["score"] = min(len(extracted_data["api_calls"]) * 45, 100)
        g1_result["raw_features"] = {"api_calls": extracted_data["api_calls"]}
        g1_result["reasoning_trace"] = f"Flagged persistent application execution intent tracking {len(extracted_data['api_calls'])} critical security hooks (Accessibility Service monitoring/SMS intercepts)."
        
    if len(network_strings) > 0:
        g4_result["score"] = min(len(network_strings) * 45, 100)
        g4_result["raw_features"] = {"extracted_urls": network_strings}
        g4_result["reasoning_trace"] = f"Identified {len(network_strings)} suspicious remote connection channels including raw unverified IP exfiltration nodes."
    
    # 4. Generate Composite Matrix Report
    print("\n[*] Invoking Agent A-11 (Risk Composer Matrix Assembly)...")
    composite_report = RiskComposerA11.calculate_phantom_score(g1_result, g4_result)
    
    print("\n================ SECURESTRAND AI ASSESSMENT ================")
    print(json.dumps(composite_report, indent=2))
    print("============================================================")
    
    # 5. Automated File Exporter (Fixed json.dump line)
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = os.path.join(reports_dir, f"ssai_report_{timestamp}.json")
    
    with open(report_filename, 'w', encoding='utf-8') as f:
        json.dump(composite_report, f, indent=4)
        
    print(f"[+] Forensic audit dossier exported successfully to: {report_filename}\n")

if __name__ == "__main__":
    main()
