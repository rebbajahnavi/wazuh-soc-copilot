"""
SOC Prompt Builder Module.
Assembles extracted Wazuh alert details and RAG context blocks
into structured mitigation guidance prompts for the LLM.
"""

from typing import Dict, List, Any
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from src.parser.alert_parser import ParsedAlert

class SOCPromptBuilder:
    @staticmethod
    def build_grounded_prompt(alert: ParsedAlert, rag_context: Dict[str, List[Dict[str, Any]]]) -> str:
        """Constructs a grounded LLM prompt using retrieved RAG context and alert data."""
        
        # Flatten RAG context by collection
        ir_text = "\n".join([f"- {item['text']}" for item in rag_context.get("general_ir", [])])
        nist_text = "\n".join([f"- {item['text']}" for item in rag_context.get("nist_csf", [])])
        mitre_text = "\n".join([f"- {item['text']}" for item in rag_context.get("mitre_attack", [])])

        prompt = f"""### SYSTEM ROLE
You are an expert Security Operations Center (SOC) Copilot. Your job is to analyze Wazuh SIEM security alerts and provide concise, actionable, and grounded incident response guidance.

### OBSERVED WAZUH ALERT
- Timestamp: {alert.timestamp}
- Endpoint: {alert.agent_name} (IP: {alert.agent_ip}, ID: {alert.agent_id})
- Severity Level: Level {alert.rule_level} (Rule ID: {alert.rule_id})
- Description: {alert.rule_description}
- Associated MITRE ATT&CK: {', '.join(alert.mitre_ids) if alert.mitre_ids else 'None specified'}
- MITRE Tactics: {', '.join(alert.mitre_tactics) if alert.mitre_tactics else 'None'}
- MITRE Techniques: {', '.join(alert.mitre_techniques) if alert.mitre_techniques else 'None'}

### RETRIEVED GROUND-TRUTH KNOWLEDGE
[GENERAL INCIDENT RESPONSE CONTEXT]
{ir_text if ir_text else 'No specific IR playbook matched.'}

[NIST CSF 2.0 CONTEXT]
{nist_text if nist_text else 'No specific NIST CSF mapping matched.'}

[MITRE ATT&CK CONTEXT]
{mitre_text if mitre_text else 'No specific MITRE mitigation matched.'}

### INSTRUCTIONS FOR RESPONSE
1. Provide a concise Incident Summary.
2. Outline Immediate Containment Actions (grounded in retrieved IR and MITRE knowledge).
3. Specify Eradication & Remediation Steps.
4. Map actions to relevant NIST CSF 2.0 categories (e.g., RS.AN, RS.MI, PR.AA).
5. State any assumptions or missing information clearly. Do not fabricate ungrounded commands.
"""
        return prompt

if __name__ == "__main__":
    import json
    from rag.retrieval.retriever import SOCRetriever
    from src.parser.alert_parser import WazuhAlertParser

    print("Testing End-to-End Alert Parsing -> RAG Retrieval -> Prompt Construction...\n")
    retriever = SOCRetriever()

    with open("data/sample/wazuh_alerts.json", "r", encoding="utf-8") as f:
        sample_alerts = json.load(f)

    # Test with first alert (T1078 Valid Accounts)
    parsed_alert = WazuhAlertParser.parse(sample_alerts[0])
    query = parsed_alert.to_retrieval_query()
    
    print(f"Retrieving context for query: {query}")
    rag_context = retriever.retrieve_unified_context(query=query, top_k_per_collection=1)

    prompt = SOCPromptBuilder.build_grounded_prompt(parsed_alert, rag_context)
    print("\n================ ASSEMBLED GROUNDED PROMPT ================")
    print(prompt)
