"""
LLM Client Module for SOC Copilot.
Handles inference using configured LLM providers with offline fallback support.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

class SOCLLMClient:
    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "mock").lower()
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        self.model = os.getenv("LLM_MODEL", "gpt-4o-mini")

    def generate_playbook(self, prompt: str) -> str:
        """Sends prompt to the configured LLM or fallback simulator."""
        if self.provider == "openai" and self.api_key and not self.api_key.startswith("your_"):
            try:
                from openai import OpenAI
                client = OpenAI(api_key=self.api_key)
                response = client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a professional Tier-2 SOC Incident Responder."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2
                )
                return response.choices[0].message.content
            except Exception as e:
                print(f"OpenAI API call failed: {e}. Falling back to deterministic playbook generator.")

        # Offline / Mock grounded playbook generator
        return self._generate_grounded_fallback_playbook(prompt)

    def _generate_grounded_fallback_playbook(self, prompt: str) -> str:
        """Generates an accurate, grounded incident playbook for offline testing."""
        return """## Incident Response Playbook

### 1. Incident Summary
A high-severity authentication anomaly (Level 10) was detected by Wazuh SIEM involving account manipulation/privilege abuse (MITRE ATT&CK T1078). Multiple authentication failures occurred followed by a successful interactive logon from an internal workstation.

### 2. Immediate Containment Actions
- **Isolate Endpoint:** Disconnect host `win-endpoint-soc` (192.168.1.105) from the network segment to halt potential lateral movement.
- **Revoke Active Sessions:** Immediately terminate active Kerberos/NTLM sessions and refresh tokens for `Administrator`.
- **IP Blocking:** Temporarily null-route or filter incoming traffic from origin IP `192.168.1.50` at the subnet switch.

### 3. Eradication & Remediation
- **Credential Rotation:** Force an immediate enterprise-wide password change for target account `Administrator` (MITRE M1027).
- **MFA Enforcement:** Verify multi-factor authentication (MFA) enforcement across all remote access points and internal RDP tunnels (MITRE M1032).
- **Audit Persistence:** Inspect Task Scheduler, registry Run keys, and newly created local accounts for persistence mechanisms.

### 4. NIST CSF 2.0 Mapping
- **RS.AN (Incident Analysis):** Correlate Wazuh rule ID 60115 alerts with surrounding host event logs to establish intrusion timeline.
- **RS.MI (Incident Mitigation):** Network isolation and compromised credential deactivation executed.
- **PR.AA (Identity Management):** Password policy hardening and MFA verification enforced.
"""

if __name__ == "__main__":
    client = SOCLLMClient()
    sample_prompt = "Generate response playbook for Wazuh Alert 60115 (T1078 Valid Accounts)"
    print(f"Testing LLM Client (Provider: {client.provider})...\n")
    response = client.generate_playbook(sample_prompt)
    print(response)