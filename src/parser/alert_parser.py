"""
Wazuh JSON Alert Parser and Extraction Engine.
Extracts severity, rule details, MITRE TTPs, and endpoint telemetry.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class ParsedAlert(BaseModel):
    timestamp: str
    rule_id: str
    rule_level: int
    rule_description: str
    agent_id: str
    agent_name: str
    agent_ip: Optional[str] = "N/A"
    mitre_ids: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    def to_retrieval_query(self) -> str:
        """Converts extracted alert fields into an embedding search query."""
        mitre_info = ""
        if self.mitre_ids:
            mitre_info = f"MITRE ATT&CK: {', '.join(self.mitre_ids)} ({', '.join(self.mitre_techniques)})"
        return f"{self.rule_description}. {mitre_info}".strip()

class WazuhAlertParser:
    @staticmethod
    def parse(alert_data: Dict[str, Any]) -> ParsedAlert:
        """Parses raw Wazuh alert JSON into a validated schema."""
        rule = alert_data.get("rule", {})
        mitre = rule.get("mitre", {})
        agent = alert_data.get("agent", {})

        return ParsedAlert(
            timestamp=alert_data.get("timestamp", "UNKNOWN"),
            rule_id=str(rule.get("id", "UNKNOWN")),
            rule_level=int(rule.get("level", 0)),
            rule_description=rule.get("description", "No description provided"),
            agent_id=str(agent.get("id", "N/A")),
            agent_name=agent.get("name", "N/A"),
            agent_ip=agent.get("ip", "N/A"),
            mitre_ids=mitre.get("id", []),
            mitre_tactics=mitre.get("tactic", []),
            mitre_techniques=mitre.get("technique", [])
        )

if __name__ == "__main__":
    import json
    with open("data/sample/wazuh_alerts.json", "r", encoding="utf-8") as f:
        sample_alerts = json.load(f)

    for i, raw_alert in enumerate(sample_alerts, 1):
        parsed = WazuhAlertParser.parse(raw_alert)
        print(f"=== Alert #{i} Parsed ===")
        print(f"Endpoint: {parsed.agent_name} ({parsed.agent_ip})")
        print(f"Severity: Level {parsed.rule_level} | Rule ID: {parsed.rule_id}")
        print(f"Description: {parsed.rule_description}")
        print(f"MITRE IDs: {parsed.mitre_ids}")
        print(f"RAG Query String: '{parsed.to_retrieval_query()}'\n")