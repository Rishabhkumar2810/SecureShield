# SecureStrand AI — Full 6-Strand Genome Model (G1–G6)

Working implementation of all six genome strands from the SecureStrand AI design:

- **G1 — Semantic Opcode Chromosome** (`g1_semantic.py`) — traces API call sequences per method to detect credential-harvest intent (e.g. read UI input → send over network with no crypto step), reasoning past obfuscated names via LLM.
- **G2 — Permission Intent Graph** (`g2_permission.py`) — builds a causal graph of dangerous permission combinations and detects intent chains (e.g. Accessibility + SMS + Internet = credential theft + exfil).
- **G3 — Linguistic Social Engineering** (`g3_linguistic.py`) — detects phishing/manipulation language and banking-brand impersonation in an APK's UI text.
- **G4 — Network Behavior Helix** (`g4_network.py`) — extracts embedded URLs/domains/IPs, scores them for DGA-style entropy and covert-channel indicators (raw sockets, hardcoded IPs).
- **G5 — Temporal Execution Rhythm** (`g5_temporal.py`) — detects sleeper/time-bomb logic that delays malicious behavior to evade sandbox analysis.
- **G6 — Supply Chain Lineage** (`g6_lineage.py`) — detects repackaged/trojanized apps via certificate analysis, unknown bundled libraries, and structural similarity to a reference APK.

All six agents pull raw data from a shared extraction layer (`apk_extractor.py`, built on Androguard), run a fast rule-based scorer, then call Claude for deeper reasoning, and return output in the standard strand schema:

```json
{ "strand": "G3", "score": 0-100, "evidence": [...], "raw_features": {...} }
```

## Files

| File | Purpose |
|---|---|
| `apk_extractor.py` | Shared APK decompilation + extraction (strings, methods, call graph, permissions, certs, libraries) |
| `g1_semantic.py` | G1 strand: opcode-category call-chain matching + LLM intent reasoning |
| `g2_permission.py` | G2 strand: permission causal graph + over-permissioning check + LLM reasoning |
| `g3_linguistic.py` | G3 strand: lexicon scoring + brand impersonation check + LLM reasoning |
| `g4_network.py` | G4 strand: URL/domain/IP extraction + entropy scoring + LLM C&C reasoning |
| `g5_temporal.py` | G5 strand: time-API detection + call-graph reachability + LLM reasoning |
| `g6_lineage.py` | G6 strand: certificate/library analysis + reference-APK similarity + LLM reasoning |
| `run_analysis.py` | CLI entry point — runs all six strands on one APK |
| `requirements.txt` | Python dependencies |

## Setup

```bash
pip install -r requirements.txt
```

You'll also need a JDK installed on your system (Androguard/decompilation tooling depends on it for some APK formats) — not required on most Linux setups but worth checking if you hit errors.

## Usage

```bash
# Full run — all 6 strands, with LLM reasoning (recommended)
export ANTHROPIC_API_KEY=sk-ant-...
python run_analysis.py path/to/app.apk

# Save output to a file
python run_analysis.py path/to/app.apk --out result.json

# Rule-based only, no API calls (fast, free, for quick testing)
python run_analysis.py path/to/app.apk --no-llm

# Include G6 reference-APK comparison (e.g. compare suspicious app against
# the real bank's official Play Store APK to detect repackaging)
python run_analysis.py path/to/suspicious.apk --reference path/to/official_bank_app.apk

# Run a single strand directly
python g1_semantic.py path/to/app.apk YOUR_API_KEY
python g2_permission.py path/to/app.apk YOUR_API_KEY
python g3_linguistic.py path/to/app.apk YOUR_API_KEY
python g4_network.py path/to/app.apk YOUR_API_KEY
python g5_temporal.py path/to/app.apk YOUR_API_KEY
python g6_lineage.py path/to/app.apk YOUR_API_KEY --reference path/to/official_bank_app.apk
```

## How each strand works

### G1 — Semantic Opcode Chromosome
1. Walks every method's decompiled instructions and tags each sensitive API call into a category (`UI_CREDENTIAL_READ`, `STORAGE_READ/WRITE`, `NETWORK_SEND`, `CRYPTO`, `REFLECTION_OBFUSCATION`, `ACCESSIBILITY_READ`)
2. Builds an ordered "opcode intent chain" per method and matches it against known malicious subsequences — e.g. `UI_CREDENTIAL_READ -> NETWORK_SEND` with **no** `CRYPTO` step in between = plaintext credential exfiltration
3. Sends flagged methods' code + matched chains to Claude, which explains intent in plain English *ignoring obfuscated variable names*, and applies a lightweight counterfactual check: "would a benign banking app plausibly need this exact call sequence?"
4. Final score = `0.45 × rule_score + 0.55 × LLM_score`

Extend `MALICIOUS_SEQUENCES` and `API_CATEGORIES` in `g1_semantic.py` as you find more patterns in real samples.

**Note on G1:** the design doc describes "LLM code embedding + Graph Neural Network." A trained GNN over a full program-dependence graph is out of scope for a hackathon build — this implementation gets the same *intent-level signal* via direct LLM reasoning over API call sequences instead, which is an honest and defensible scoping choice.

### G2 — Permission Intent Graph
1. Pulls declared permissions from the manifest, and (where the Analysis engine can determine it) which permissions are actually exercised by code vs. just declared
2. Builds a directed graph (`networkx`) of known dangerous permission **combinations** — not single permissions, but causal chains like `ACCESSIBILITY_SERVICE + READ_SMS + INTERNET` = read screen/SMS then exfiltrate over network
3. Flags over-permissioning: sensitive permissions requested but never used in code
4. Sends the matched combos + full permission list to Claude, which reasons causally about what the *combination* enables end-to-end and rates malicious intent
5. Final score = `0.5 × rule_score + 0.5 × LLM_score`

Extend `DANGEROUS_COMBOS` in `g2_permission.py` with more chains as you find them in real samples — that list is the actual "Permission Intent Graph."

### G3 — Linguistic Social Engineering
1. Extracts every UI string from `strings.xml`, layout files, and decompiled bytecode literals
2. Filters out garbage (IDs, paths, non-sentence strings)
3. Scores against urgency / authority / credential-harvest lexicons
4. Fuzzy-matches app name against known bank names, checks if signing certificate matches that bank's known cert (flag mismatch = impersonation signal)
5. Sends flagged strings to Claude for structured phishing-intent reasoning
6. Final score = `0.4 × rule_score + 0.6 × LLM_score`

### G4 — Network Behavior Helix
1. Extracts every URL/domain/IP literal from the APK's full string pool (not just UI text — hidden endpoints usually aren't shown to the user)
2. Scores domains with Shannon entropy (high-entropy labels look like DGA-generated C&C domains) and flags suspicious TLDs commonly abused for disposable infrastructure
3. Flags hardcoded raw IP addresses (legit apps almost never hardcode IPs — they use DNS so infra can rotate cleanly) and raw `Socket`/`DatagramSocket` usage (bypasses standard HTTPS/cert-pinning inspection — a covert-channel signal)
4. Sends the full endpoint list + API usage pattern to Claude, which reasons about C&C likelihood versus normal legitimate infrastructure (analytics SDKs, payment gateways, CDNs)
5. Final score = `0.4 × rule_score + 0.6 × LLM_score`

**Note on G4:** this is static/offline analysis only — no live DNS resolution, WHOIS, or threat-intel API lookups (VirusTotal, etc.). Wiring in a live threat-feed check against `flagged_domains` is the natural next step for production and would strengthen the C&C match significantly.

### G5 — Temporal Execution Rhythm
1. Scans every method's bytecode for time-related APIs (`AlarmManager`, `Handler.postDelayed`, `System.currentTimeMillis`, `BOOT_COMPLETED` receivers)
2. For each time-gated method, walks the call graph (Androguard `xref_to`) up to 2 hops to check if it reaches a sensitive sink (SMS send, network POST, Accessibility abuse, data harvest)
3. Sends each such "gated path" to Claude, which reads the raw bytecode and explains the trigger condition in plain English (e.g. *"activates 72 hours after install"*)
4. Final score = `0.5 × rule_score + 0.5 × (avg LLM evasion_likelihood × 100)`

**Note on G5:** this is a static-heuristic approximation of symbolic execution (reachability analysis + LLM reasoning), not a full path-condition solver like Amandroid/FlowDroid. It's a realistic scope for a hackathon build and still produces the same style of "sleeper trigger" narrative the design doc describes — but flag this scoping choice honestly if judges ask about "symbolic execution."

### G6 — Supply Chain Lineage
1. Extracts certificate details (issuer, self-signed check), all bundled top-level packages, and known repackaging-tool artifacts (e.g. `apktool.yml` left behind by a rebuild)
2. Classifies bundled libraries against a known-SDK allowlist (Firebase, OkHttp, Glide, etc.) — anything unmatched is flagged as unclassified third-party code worth reviewing
3. **Optional but most powerful signal:** pass `--reference path/to/official_app.apk` (the real bank's Play Store APK) — G6 computes Jaccard similarity over class-name sets between the two. High similarity (shared code) + different signing certificate = classic repackaging/trojan-injection pattern
4. Sends all of this to Claude, which writes a provenance narrative judging whether the app is original, a trojanized repackage, or inconclusive
5. Final score = `0.4 × rule_score + 0.6 × LLM_score`

**Note on G6:** the similarity-hashing signal is only as strong as the reference APK you provide. Without a reference, G6 still works off certificate/library heuristics alone, but it's meaningfully weaker — for a real demo, grab the official APK of whatever bank app you're testing against from the Play Store (via `apkpure`/`apkmirror` or similar) and pass it as `--reference`.

## Wiring into the full SecureStrand pipeline

All six `analyze()` methods return a dict matching your strand schema exactly, so `A-11 Risk Composer` can consume them directly:

```python
g1_out = G1SemanticAnalyzer(extractor, api_key).analyze()
g2_out = G2PermissionAnalyzer(extractor, api_key).analyze()
g3_out = G3LinguisticAnalyzer(extractor, api_key).analyze()
g4_out = G4NetworkAnalyzer(extractor, api_key).analyze()
g5_out = G5TemporalAnalyzer(extractor, api_key).analyze()
g6_out = G6LineageAnalyzer(extractor, api_key, reference_extractor=ref_extractor).analyze()

phantom_score = (
    g1_out["score"] * 0.20   # G1 base weight
    + g2_out["score"] * 0.18  # G2 base weight
    + g3_out["score"] * 0.15  # G3 base weight
    + g4_out["score"] * 0.18  # G4 base weight
    + g5_out["score"] * 0.14  # G5 base weight
    + g6_out["score"] * 0.15  # G6 base weight
)
```

Base weights above match the Phantom Score table in the design doc (Section 5). All strand outputs feed directly into `A-10 Narrator AI`'s prompt via their `evidence` lists to build the forensic dossier paragraph.

The `evidence` lists from each strand feed straight into `A-10 Narrator AI`'s prompt to build the forensic dossier paragraph.

## Testing

Test against a mix of:
- Known-clean APKs (should score low on both strands)
- Sample banking-trojan APKs from a malware research dataset (e.g. AndroZoo, with proper institutional access/ethics clearance)

Never test against live/unknown APKs on a machine connected to production banking systems — always run in an isolated sandbox VM.
