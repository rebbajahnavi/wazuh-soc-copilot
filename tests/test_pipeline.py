"""
End-to-End Verification Test Suite for Wazuh SOC Copilot.
Validates each component sequentially: Parser -> Embeddings -> Qdrant -> Retrieval -> Prompt -> Playbook.
"""

import sys
import json
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

from src.parser.alert_parser import WazuhAlertParser, ParsedAlert
from rag.vector_db.qdrant_manager import QdrantManager
from rag.retrieval.retriever import SOCRetriever
from src.llm.prompt_builder import SOCPromptBuilder
from src.llm.llm_client import SOCLLMClient

class TestSOCCopilotPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Loads shared resources once for the test run."""
        cls.alerts_path = ROOT_DIR / "data" / "sample" / "wazuh_alerts.json"
        with open(cls.alerts_path, "r", encoding="utf-8") as f:
            cls.raw_alerts = json.load(f)
        cls.retriever = SOCRetriever()
        cls.llm_client = SOCLLMClient()

    def test_01_alert_parsing(self):
        parsed = WazuhAlertParser.parse(self.raw_alerts[0])
        self.assertIsInstance(parsed, ParsedAlert)
        self.assertEqual(parsed.rule_id, "60115")
        self.assertEqual(parsed.rule_level, 10)
        self.assertIn("T1078", parsed.mitre_ids)

    def test_02_embedding_dimension(self):
        encoder = self.retriever.encoder
        test_vec = encoder.embed_text("Test security event")
        self.assertEqual(test_vec.shape, (1, 1024))

    def test_03_qdrant_collections_exist(self):
        manager = QdrantManager()
        cols = [c.name for c in manager.client.get_collections().collections]
        self.assertIn("general_ir", cols)
        self.assertIn("nist_csf", cols)
        self.assertIn("mitre_attack", cols)

    def test_04_rag_retrieval_quality(self):
        parsed = WazuhAlertParser.parse(self.raw_alerts[0])
        query = parsed.to_retrieval_query()
        context = self.retriever.retrieve_unified_context(query, top_k_per_collection=1)

        self.assertTrue(len(context["general_ir"]) > 0)
        self.assertTrue(len(context["nist_csf"]) > 0)
        self.assertTrue(len(context["mitre_attack"]) > 0)

        for col, hits in context.items():
            self.assertGreater(hits[0]["score"], 0.3)

    def test_05_playbook_generation(self):
        parsed = WazuhAlertParser.parse(self.raw_alerts[0])
        context = self.retriever.retrieve_unified_context(parsed.to_retrieval_query(), top_k_per_collection=1)
        prompt = SOCPromptBuilder.build_grounded_prompt(parsed, context)
        playbook = self.llm_client.generate_playbook(prompt)

        self.assertIn("Incident Summary", playbook)
        self.assertIn("Containment", playbook)
        self.assertIn("NIST CSF", playbook)

if __name__ == "__main__":
    unittest.main(verbosity=2)