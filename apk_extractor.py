"""
apk_extractor.py
-----------------
Shared extraction layer for SecureStrand AI.
Both G3 (Linguistic) and G5 (Temporal) agents use this module to pull
raw material out of an APK before running their own analysis on top.

Requires: androguard  (pip install androguard --break-system-packages)
"""

import re
from androguard.misc import AnalyzeAPK


class APKExtractor:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        # AnalyzeAPK returns (APK object, list of DalvikVMFormat, Analysis object)
        self.apk, self.dvms, self.analysis = AnalyzeAPK(apk_path)

    # ------------------------------------------------------------------
    # Used by G3 — pulls every human-readable UI string out of the app
    # ------------------------------------------------------------------
    def get_ui_strings(self):
        strings = set()

        # 1. strings.xml / arsc resources
        try:
            for _, _, value in self.apk.get_android_resources().get_resolved_strings_table(self.apk.get_package(), 0):
                strings.add(value)
        except Exception:
            pass

        # fallback: simpler resource string dump (works across androguard versions)
        try:
            arsc = self.apk.get_android_resources()
            for package_name in arsc.get_packages_names():
                for locale in arsc.get_locales(package_name):
                    res = arsc.get_string_resources(package_name, locale)
                    for line in res.decode("utf-8", errors="ignore").splitlines():
                        m = re.search(r'>([^<>]{4,})<', line)
                        if m:
                            strings.add(m.group(1).strip())
        except Exception:
            pass

        # 2. literal strings embedded in the bytecode (Toast, AlertDialog, SMS text, etc.)
        for dvm in self.dvms:
            for s in dvm.get_strings():
                if self._looks_like_ui_text(s):
                    strings.add(s.strip())

        return sorted(strings)

    @staticmethod
    def _looks_like_ui_text(s: str) -> bool:
        """Cheap filter: keep only strings that look like real sentences,
        not resource IDs, package names, class paths, base64 blobs, etc."""
        if not s or len(s) < 8 or len(s) > 300:
            return False
        if re.match(r'^[A-Za-z0-9_./$;\\-]+$', s) and " " not in s:
            return False  # looks like a path/identifier, not a sentence
        if not re.search(r'[a-zA-Z]{3,}\s+[a-zA-Z]{2,}', s):
            return False  # needs at least two real words
        return True

    def get_app_label_and_package(self):
        return self.apk.get_app_name(), self.apk.get_package()

    def get_signing_cert_fingerprint(self):
        try:
            certs = self.apk.get_certificates()
            if certs:
                return certs[0].sha256_fingerprint
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Used by G5 — pulls every method body as text + builds a call graph
    # ------------------------------------------------------------------
    def get_all_methods_source(self):
        """Returns list of dicts: {class_name, method_name, code_lines, method_obj}"""
        methods = []
        for dvm in self.dvms:
            for cls in dvm.get_classes():
                for method in cls.get_methods():
                    code = method.get_code()
                    if code is None:
                        continue
                    lines = []
                    try:
                        for instr in code.get_bc().get_instructions():
                            lines.append(instr.get_output())
                    except Exception:
                        continue
                    methods.append({
                        "class_name": cls.get_name(),
                        "method_name": method.get_name(),
                        "full_signature": f"{cls.get_name()}->{method.get_name()}",
                        "code_lines": lines,
                        "method_obj": method,
                    })
        return methods

    def get_call_graph_analysis(self):
        """Returns the androguard Analysis object which already has
        xref_to / xref_from for every method — used for reachability checks."""
        return self.analysis

    # ------------------------------------------------------------------
    # Used by G2 — permission list + which permissions are actually
    # exercised in code (vs just declared, i.e. over-permissioning)
    # ------------------------------------------------------------------
    def get_declared_permissions(self):
        try:
            return sorted(self.apk.get_permissions())
        except Exception:
            return []

    def get_used_permissions(self):
        """Cross-references declared permissions against the API calls the
        Analysis engine can see being used — gives us the 'requested but
        never exercised' signal (classic over-permissioning red flag)."""
        used = set()
        try:
            for perm, api_list in self.analysis.get_permissions_used().items():
                if api_list:
                    used.add(perm)
        except Exception:
            # Older/newer androguard versions expose this differently —
            # fall back to declared list if the API isn't available.
            return set(self.get_declared_permissions())
        return used

    def has_accessibility_service_declared(self):
        """Checks the manifest for a declared AccessibilityService component,
        a very strong banking-trojan overlay-attack signal when combined
        with BIND_ACCESSIBILITY_SERVICE."""
        try:
            xml = self.apk.get_android_manifest_xml()
            manifest_str = xml.toxml() if hasattr(xml, "toxml") else str(xml)
            return "accessibilityservice" in manifest_str.lower() or \
                   "BIND_ACCESSIBILITY_SERVICE" in manifest_str
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Used by G6 — certificate, library, and structural fingerprint info
    # ------------------------------------------------------------------
    def get_certificate_details(self):
        details = {"fingerprint_sha256": None, "issuer": None, "subject": None,
                   "is_self_signed": None, "not_before": None, "not_after": None}
        try:
            certs = self.apk.get_certificates()
            if certs:
                cert = certs[0]
                details["fingerprint_sha256"] = cert.sha256_fingerprint
                details["issuer"] = str(cert.issuer)
                details["subject"] = str(cert.subject)
                details["is_self_signed"] = (str(cert.issuer) == str(cert.subject))
                details["not_before"] = str(getattr(cert, "not_valid_before", ""))
                details["not_after"] = str(getattr(cert, "not_valid_after", ""))
        except Exception:
            pass
        return details

    def get_all_class_names(self):
        """Every class name in the dex — used as a structural fingerprint
        for similarity comparison against a reference (known-legit) APK."""
        names = set()
        for dvm in self.dvms:
            for cls in dvm.get_classes():
                names.add(cls.get_name())
        return names

    def get_top_level_packages(self):
        """Groups class names into top-level package prefixes so we can
        separate 'app's own code' from bundled third-party SDKs/libraries."""
        packages = {}
        for name in self.get_all_class_names():
            clean = name.strip("L;").replace("/", ".")
            parts = clean.split(".")
            if len(parts) >= 3:
                prefix = ".".join(parts[:3])
                packages[prefix] = packages.get(prefix, 0) + 1
        return packages

    def get_file_hash(self):
        import hashlib
        h = hashlib.sha256()
        with open(self.apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def has_repackaging_markers(self):
        """Looks for artifacts commonly left behind by APK rebuild/resign
        tools (apktool, common cracking/repackaging utilities)."""
        markers_found = []
        try:
            file_names = self.apk.get_files()
            marker_patterns = [
                "apktool.yml", "META-INF/CERT.SF", "smali_assets",
                "assets/apktool", "res/values/public.xml.orig",
            ]
            for fname in file_names:
                for marker in marker_patterns:
                    if marker in fname:
                        markers_found.append(fname)
        except Exception:
            pass
        return markers_found

    # ------------------------------------------------------------------
    # Used by G1 — every raw literal string in the dex (unfiltered, unlike
    # get_ui_strings which only keeps sentence-like text). G1 needs this
    # because credential-harvest logic often references field names, API
    # paths, or short tokens that get_ui_strings would discard.
    # ------------------------------------------------------------------
    def get_all_literal_strings(self):
        strings = set()
        for dvm in self.dvms:
            for s in dvm.get_strings():
                if s and len(s.strip()) > 0:
                    strings.add(s.strip())
        return strings
