import re

class G4NetworkExtractor:
    def __init__(self, raw_strings: list):
        self.raw_strings = raw_strings
        self.url_regex = re.compile(r'https?://[^\s"\'>]+')
        self.ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    def extract_features(self) -> dict:
        extracted_urls = set()
        extracted_ips = set()
        for text in self.raw_strings:
            urls = self.url_regex.findall(text)
            for url in urls:
                extracted_urls.add(url)
            ips = self.ip_regex.findall(text)
            for ip in ips:
                extracted_ips.add(ip)
        return {
            "extracted_urls": list(extracted_urls),
            "protocols_used": ["HTTP/HTTPS"],
            "covert_channels": False
        }
