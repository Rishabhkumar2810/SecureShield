import os
import re

class DecompilerSageA01:
    """Implements basic static file extraction for Agent A-01."""
    
    @staticmethod
    def extract_features_from_file(file_path: str) -> dict:
        print(f"[*] Agent A-01 scanning target path: {file_path}")
        
        extracted_apis = []
        extracted_urls = []
        
        if not os.path.exists(file_path):
            print(f"[!] Target file not found: {file_path}")
            return {"api_calls": [], "extracted_urls": []}
            
        # Regex to find standard web links
        url_pattern = re.compile(r'https?://[^\s"\']+')
        # Regex to flag direct unverified IP communication (e.g., http://192.168.1.1:8080)
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/\s"\']?')
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Scan for standard links or direct IPs
                    if ip_pattern.search(line):
                        ips = ip_pattern.findall(line)
                        extracted_urls.extend([ip.strip('"\'' ) for ip in ips])
                    else:
                        urls = url_pattern.findall(line)
                        if urls:
                            extracted_urls.extend(urls)
                        
                    # --- G1 Semantic Rule Expansion ---
                    # 1. Catch SMS Interception patterns
                    if any(x in line for x in ["SmsReceiver", "onReceive", "SMS_RECEIVED"]):
                        extracted_apis.append("com.secure.banking.SmsReceiver.onReceive")
                    
                    # 2. Catch Accessibility Service Abuse (Common in Banking Trojans for overlays)
                    if any(x in line.lower() for x in ["accessibilityservice", "accessibility_service", "onaccessibilityevent"]):
                        extracted_apis.append("android.accessibilityservice.AccessibilityService")
                        
                    # 3. Catch Device Administrator / Installation manipulation attempts
                    if any(x in line for x in ["DEVICE_ADMIN_ENABLED", "requestRole", "ACTION_MANAGE_OVERLAYS"]):
                        extracted_apis.append("android.app.role.RoleManager")
                        
        except Exception as e:
            print(f"[!] Error processing file: {str(e)}")
            
        return {
            "api_calls": list(set(extracted_apis)),
            "extracted_urls": list(set(extracted_urls))
        }
