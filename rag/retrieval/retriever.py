"""
Multi-collection semantic retrieval engine for SOC playbooks.
Auto-checks and populates collections if running in fresh environments (like Streamlit Cloud).
"""

from typing import Dict, List, Any
from rag.vector_db.qdrant_manager import QdrantManager
from rag.embeddings.encoder import EmbeddingEncoder

class SOCRetriever:
    def __init__(self):
        self.encoder = EmbeddingEncoder()
        self.db_manager = QdrantManager()
        self._ensure_knowledge_base()

    def _ensure_knowledge_base(self):
        """Auto-populates Qdrant collections if they do not exist."""
        required_collections = ["general_ir", "nist_csf", "mitre_attack"]
        existing = [c.name for c in self.db_manager.client.get_collections().collections]
        
        needs_ingestion = any(col not in existing for col in required_collections)
        if needs_ingestion:
            try:
                from rag.ingestion.ingest import ingest_all_knowledge
                ingest_all_knowledge()
            except Exception as e:
                print(f"Ingestion check: {e}")

    def retrieve_from_collection(self, collection_name: str, query: str, top_k: int = 2) -> List[Dict[str, Any]]:
        query_vector = self.encoder.encode_query(query)
        try:
            results = self.db_manager.client.search(
                collection_name=collection_name,
                query_vector=query_vector,
                limit=top_k
            )
            return [
                {
                    "score": hit.score,
                    "content": hit.payload.get("content", ""),
                    "metadata": hit.payload.get("metadata", {})
                }
                for hit in results
            ]
        except Exception:
            return []

    def retrieve_unified_context(self, query: str, top_k_per_collection: int = 1) -> Dict[str, List[Dict[str, Any]]]:
        collections = ["general_ir", "nist_csf", "mitre_attack"]
        context = {}
        for col_name in collections:
            context[col_name] = self.retrieve_from_collection(
                collection_name=col_name,
                query=query,
                top_k=top_k_per_collection
            )
        return context