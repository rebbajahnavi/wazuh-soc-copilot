"""
Semantic Retriever for SOC Copilot.
Queries Qdrant collections using cosine similarity to fetch top-K relevant chunks.
"""

import sys
from pathlib import Path
from typing import List, Dict, Any

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from rag.embeddings.encoder import EmbeddingEncoder
from rag.vector_db.qdrant_manager import QdrantManager

class SOCRetriever:
    def __init__(self, storage_path: str = "./qdrant_storage"):
        """Initializes encoder and local Qdrant client."""
        self.encoder = EmbeddingEncoder()
        self.manager = QdrantManager(storage_path=storage_path)
        self.client = self.manager.client

    def retrieve_from_collection(self, query: str, collection_name: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """Searches a specific collection for top-K matching records."""
        query_vector = self.encoder.embed_text(query)[0].tolist()

        search_results = self.client.query_points(
            collection_name=collection_name,
            query=query_vector,
            limit=top_k
        ).points

        hits = []
        for point in search_results:
            hits.append({
                "collection": collection_name,
                "score": round(float(point.score), 4),
                "source": point.payload.get("source"),
                "text": point.payload.get("text")
            })
        return hits

    def retrieve_unified_context(self, query: str, top_k_per_collection: int = 2) -> Dict[str, List[Dict[str, Any]]]:
        """Queries all 3 collections to assemble comprehensive incident response context."""
        context = {}
        for col_name in ["general_ir", "nist_csf", "mitre_attack"]:
            context[col_name] = self.retrieve_from_collection(
                query=query, 
                collection_name=col_name, 
                top_k=top_k_per_collection
            )
        return context

if __name__ == "__main__":
    retriever = SOCRetriever()
    test_query = "Adversary abusing compromised credentials T1078 to gain persistence"
    print(f"\nTesting retrieval for query: '{test_query}'\n")

    results = retriever.retrieve_unified_context(test_query, top_k_per_collection=1)

    for col, records in results.items():
        print(f"=== Top match from collection: {col} ===")
        for rec in records:
            print(f"Score: {rec['score']} | Source: {rec['source']}")
            print(f"Snippet: {rec['text'][:150]}...\n")