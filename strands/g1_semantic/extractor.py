import re

class G1SemanticExtractor:
    def __init__(self, structural_nodes: list):
        self.nodes = structural_nodes
        self.sensitive_apis = ["SmsManager", "AccessibilityService", "DexClassLoader", "Crypto", "Cipher"]

    def extract_features(self) -> dict:
        suspicious_methods = []
        api_calls = set()
        for node in self.nodes:
            method_name = node.get("method", "")
            class_name = node.get("class", "")
            descriptor = node.get("descriptor", "")
            for api in self.sensitive_apis:
                if api in class_name or api in descriptor:
                    api_calls.add(f"{class_name}->{method_name}")
        return {
            "suspicious_methods": suspicious_methods,
            "api_calls": list(api_calls),
            "obfuscation_level": "low"
        }
