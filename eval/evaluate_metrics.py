"""
Performance Evaluation Module for SOC Copilot.
Evaluates generated playbooks against expert ground-truth benchmarks
using Cosine Similarity (via BAAI/bge-large-en-v1.5) and BERTScore (P, R, F1).
"""

import sys
from pathlib import Path
import pandas as pd
from bert_score import score as bert_score_eval

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

from rag.embeddings.encoder import EmbeddingEncoder

# Benchmark Ground-Truth Playbook for Wazuh Alert 60115 (T1078 Valid Accounts)
GROUND_TRUTH_PLAYBOOK = """## Ground-Truth Incident Response Playbook
Incident Summary: High severity credential compromise and privilege abuse detected on Windows workstation.
Immediate Containment: Disconnect host win-endpoint-soc from network. Terminate active sessions and Kerberos tokens for Administrator. Block incoming traffic from source IP.
Eradication & Remediation: Reset compromised account passwords immediately. Audit active directory and enforce multi-factor authentication across all endpoints. Check persistence mechanisms in registry and scheduled tasks.
NIST CSF 2.0: RS.AN incident analysis, RS.MI host isolation, and PR.AA credential policy enforcement.
"""

# Copilot Generated Playbook
GENERATED_PLAYBOOK = """## Incident Response Playbook
### 1. Incident Summary
A high-severity authentication anomaly (Level 10) was detected by Wazuh SIEM involving account manipulation/privilege abuse (MITRE ATT&CK T1078). Multiple authentication failures occurred followed by a successful interactive logon from an internal workstation.
### 2. Immediate Containment Actions
- **Isolate Endpoint:** Disconnect host win-endpoint-soc (192.168.1.105) from the network segment to halt potential lateral movement.
- **Revoke Active Sessions:** Immediately terminate active Kerberos/NTLM sessions and refresh tokens for Administrator.
- **IP Blocking:** Temporarily null-route or filter incoming traffic from origin IP 192.168.1.50 at the subnet switch.
### 3. Eradication & Remediation
- **Credential Rotation:** Force an immediate enterprise-wide password change for target account Administrator (MITRE M1027).
- **MFA Enforcement:** Verify multi-factor authentication (MFA) enforcement across all remote access points and internal RDP tunnels (MITRE M1032).
- **Audit Persistence:** Inspect Task Scheduler, registry Run keys, and newly created local accounts for persistence mechanisms.
### 4. NIST CSF 2.0 Mapping
- **RS.AN (Incident Analysis):** Correlate Wazuh rule ID 60115 alerts with surrounding host event logs to establish intrusion timeline.
- **RS.MI (Incident Mitigation):** Network isolation and compromised credential deactivation executed.
- **PR.AA (Identity Management):** Password policy hardening and MFA verification enforced.
"""

def evaluate():
    print("Running Quantitative Playbook Evaluation...\n")
    
    # 1. Cosine Similarity via BAAI/bge-large-en-v1.5
    print("Computing Semantic Cosine Similarity...")
    encoder = EmbeddingEncoder()
    vec_gt = encoder.embed_text(GROUND_TRUTH_PLAYBOOK)[0]
    vec_gen = encoder.embed_text(GENERATED_PLAYBOOK)[0]
    cosine_sim = float(vec_gt @ vec_gen)  # Vectors are normalized

    # 2. BERTScore Evaluation (Precision, Recall, F1)
    print("Computing BERTScore (Precision, Recall, F1)...")
    P, R, F1 = bert_score_eval(
        [GENERATED_PLAYBOOK], 
        [GROUND_TRUTH_PLAYBOOK], 
        lang="en", 
        verbose=False
    )
    
    results = {
        "Metric": [
            "Cosine Similarity (BGE-Large)", 
            "BERTScore Precision", 
            "BERTScore Recall", 
            "BERTScore F1"
        ],
        "Score": [
            round(cosine_sim, 4),
            round(P.item(), 4),
            round(R.item(), 4),
            round(F1.item(), 4)
        ]
    }
    
    df = pd.DataFrame(results)
    out_dir = ROOT_DIR / "eval" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_dir / "evaluation_summary.csv", index=False)
    
    print("\n================ EVALUATION RESULTS ================")
    print(df.to_string(index=False))
    print(f"\nResults saved to: {out_dir / 'evaluation_summary.csv'}")

if __name__ == "__main__":
    evaluate()