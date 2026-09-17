"""
Qdrant Vector Database Manager.
Configures local storage and manages collections for:
- general_ir
- nist_csf
- mitre_attack
Configured with Cosine Distance as specified in the research paper.
"""

from typing import List, Dict, Any
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

VECTOR_DIMENSION = 1024  # Matches BAAI/bge-large-en-v1.5 output dimension

COLLECTIONS = [
    "general_ir",
    "nist_csf",
    "mitre_attack"
]

class QdrantManager:
    def __init__(self, storage_path: str = "./qdrant_storage"):
        """Initializes a local persistent Qdrant client."""
        self.client = QdrantClient(path=storage_path)
        self.vector_dim = VECTOR_DIMENSION

    def init_collections(self):
        """Creates the 3 collections if they do not already exist."""
        existing = [col.name for col in self.client.get_collections().collections]
        for col_name in COLLECTIONS:
            if col_name not in existing:
                self.client.create_collection(
                    collection_name=col_name,
                    vectors_config=VectorParams(size=self.vector_dim, distance=Distance.COSINE),
                )
                print(f"Collection created: {col_name}")
            else:
                print(f"Collection already exists: {col_name}")

    def upsert_records(self, collection_name: str, points: List[PointStruct]):
        """Inserts or updates vector points in the specified collection."""
        self.client.upsert(
            collection_name=collection_name,
            points=points
        )
        print(f"Upserted {len(points)} records into '{collection_name}'.")

    def get_collection_info(self, collection_name: str) -> Dict[str, Any]:
        """Returns collection details such as vector count."""
        return self.client.get_collection(collection_name=collection_name)

if __name__ == "__main__":
    qm = QdrantManager()
    qm.init_collections()