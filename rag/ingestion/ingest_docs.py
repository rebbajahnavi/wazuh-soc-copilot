"""
Document Ingestion and Vector Indexing.
Reads knowledge documents, embeds content chunks, and loads them into Qdrant.
"""

import sys
from pathlib import Path
import uuid
from qdrant_client.models import PointStruct

# Add project root to Python search path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from rag.embeddings.encoder import EmbeddingEncoder
from rag.vector_db.qdrant_manager import QdrantManager

KNOWLEDGE_MAPPINGS = {
    "data/knowledge/general_ir.txt": "general_ir",
    "data/knowledge/nist_csf_2_0.txt": "nist_csf",
    "data/knowledge/mitre_attack.txt": "mitre_attack",
}

def parse_chunks(file_path: str):
    """Splits structured text files into individual reference chunks."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    
    # Split by double newline or DOCUMENT header delimiter
    raw_blocks = content.split("\n\n")
    chunks = [b.strip() for b in raw_blocks if len(b.strip()) > 30]
    return chunks

def run_ingestion():
    print("Starting Knowledge-Base Ingestion...")
    encoder = EmbeddingEncoder()
    manager = QdrantManager()
    manager.init_collections()

    for file_path, collection_name in KNOWLEDGE_MAPPINGS.items():
        p = Path(file_path)
        if not p.exists():
            print(f"Warning: File {file_path} not found. Skipping.")
            continue

        chunks = parse_chunks(file_path)
        print(f"\nProcessing '{file_path}' -> Collection: '{collection_name}' ({len(chunks)} chunks)")

        points = []
        for idx, chunk_text in enumerate(chunks):
            embedding = encoder.embed_text(chunk_text)[0].tolist()
            point = PointStruct(
                id=str(uuid.uuid4()),
                vector=embedding,
                payload={
                    "source": str(p.name),
                    "chunk_id": idx,
                    "text": chunk_text
                }
            )
            points.append(point)

        manager.upsert_records(collection_name=collection_name, points=points)

    print("\nIngestion complete! All knowledge bases successfully indexed into Qdrant.")

if __name__ == "__main__":
    run_ingestion()