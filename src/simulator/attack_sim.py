"""
Atomic Red Team Attack Simulation & Telemetry Generator.
Generates controlled attack telemetry events (T1078, T1486)
to demonstrate end-to-end SIEM detection and Copilot triage.
"""

import sys
import json
import time
from pathlib import Path
from datetime import datetime

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(ROOT_DIR))

from src.parser.alert_parser import WazuhAlertParser
from rag.retrieval.retriever import SOCRetriever
from src.llm.prompt_builder import SOCPromptBuilder
from src.llm.llm_client import SOCLLMClient

SIMULATED_ATTACKS = {
    "T1078": {
        "name": "Valid Accounts - Privilege Abuse",
        "tactic": "Initial Access / Privilege Escalation",
        "payload": {
            "timestamp": datetime.utcnow().isoformat() + "+0000",
            "rule": {
                "level": 10,
                "description": "Logon failure - Unknown user name or bad password followed by successful login",
                "id": "60115",
                "mitre": {
                    "id": ["T1078"],
                    "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                    "technique": ["Valid Accounts"]
                }
            },
            "agent": {
                "id": "001",
                "name": "win-endpoint-soc",
                "ip": "192.168.1.105"
            },
            "data": {
                "win": {
                    "eventdata": {
                        "targetUserName": "Administrator",
                        "ipAddress": "192.168.1.50",
                        "logonType": "3"
                    }
                }
            }
        }
    },
    "T1486": {
        "name": "Data Encrypted for Impact - Ransomware Simulation",
        "tactic": "Impact",
        "payload": {
            "timestamp": datetime.utcnow().isoformat() + "+0000",
            "rule": {
                "level": 12,
                "description": "Mass file modification detected with known ransomware extensions (.locked)",
                "id": "100201",
                "mitre": {
                    "id": ["T1486"],
                    "tactic": ["Impact"],
                    "technique": ["Data Encrypted for Impact"]
                }
            },
            "agent": {
                "id": "002",
                "name": "srv-file-backup",
                "ip": "192.168.1.200"
            },
            "data": {
                "srcuser": "system_svc",
                "action": "bulk_rename"
            }
        }
    }
}

def execute_simulation(technique_id: str):
    attack = SIMULATED_ATTACKS.get(technique_id)
    if not attack:
        print(f"Unknown technique ID: {technique_id}")
        return

    print(f"\n[SIMULATION] Triggering Atomic Attack: {attack['name']} ({technique_id})")
    print(f"[SIMULATION] Generating Wazuh SIEM telemetry...")
    time.sleep(1)

    raw_event = attack["payload"]
    parsed_alert = WazuhAlertParser.parse(raw_event)
    print(f"[CO-PILOT] Alert detected! Rule ID: {parsed_alert.rule_id} (Level {parsed_alert.rule_level})")
    print(f"[CO-PILOT] Target Endpoint: {parsed_alert.agent_name} ({parsed_alert.agent_ip})")

    retriever = SOCRetriever()
    query = parsed_alert.to_retrieval_query()
    print(f"[CO-PILOT] Fetching grounded knowledge for: '{query}'...")
    rag_context = retriever.retrieve_unified_context(query=query, top_k_per_collection=1)

    prompt = SOCPromptBuilder.build_grounded_prompt(parsed_alert, rag_context)
    llm_client = SOCLLMClient()
    
    print("[CO-PILOT] Generating Incident Response Playbook...\n")
    playbook = llm_client.generate_playbook(prompt)
    print(playbook)

if __name__ == "__main__":
    technique = sys.argv[1] if len(sys.argv) > 1 else "T1078"
    execute_simulation(technique)