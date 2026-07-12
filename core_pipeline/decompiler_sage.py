import os
import sys
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dxml import DEX

class DecompilerSage:
    """
    Agent A-01: Responsible for APK ingestion, parsing structure,
    and normalization for downstream genome strand extractors.
    """
    def __init__(self, apk_path: str):
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK not found at target path: {apk_path}")
        self.apk_path = apk_path
        self.apk = None
        
    def extract_manifest_details(self) -> dict:
        """Extracts permissions, intent filters, and basic package metadata."""
        print(f"[*] Parsing Manifest for: {os.path.basename(self.apk_path)}")
        self.apk = APK(self.apk_path)
        
        manifest_data = {
            "package_name": self.apk.get_package(),
            "permissions": self.apk.get_permissions(),
            "activities": self.apk.get_activities(),
            "services": self.apk.get_services(),
            "receivers": self.apk.get_receivers()
        }
        return manifest_data

    def normalize_bytecode_features(self) -> list:
        """Parses classes and method definitions from DEX bytecode."""
        print("[*] Normalizing bytecode sequences...")
        normalized_methods = []
        
        # Analyze dex files packed inside the APK
        for dex_file in self.apk.get_all_dex():
            dex_obj = DEX(dex_file)
            for cls in dex_obj.get_classes():
                class_name = cls.get_name()
                for method in cls.get_methods():
                    method_name = method.get_name()
                    # Capture signature details for structural tracking
                    normalized_methods.append({
                        "class": class_name,
                        "method": method_name,
                        "descriptor": method.get_descriptor()
                    })
        return normalized_methods

    def process_apk(self) -> dict:
        """Executes the full structural processing normalization pipeline."""
        manifest = self.extract_manifest_details()
        bytecode = self.normalize_bytecode_features()
        
        return {
            "metadata": manifest,
            "structural_ast_nodes": bytecode
        }

if __name__ == "__main__":
    # Quick test harness execution block
    if len(sys.argv) < 2:
        print("Usage: python decompiler_sage.py <path_to_apk>")
    else:
        sage = DecompilerSage(sys.argv[1])
        data = sage.process_apk()
        print(f"[+] Successfully extracted {len(data['structural_ast_nodes'])} code structures.")