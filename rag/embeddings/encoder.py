"""
Embedding generator module using BAAI/bge-large-en-v1.5.
Maps security documentation and Wazuh query text into 1024-dimensional vectors.
"""

from typing import List, Union
from sentence_transformers import SentenceTransformer
import numpy as np

DEFAULT_MODEL_NAME = "BAAI/bge-large-en-v1.5"

class EmbeddingEncoder:
    def __init__(self, model_name: str = DEFAULT_MODEL_NAME):
        """Initializes the SentenceTransformer embedding model."""
        self.model_name = model_name
        print(f"Loading embedding model: {self.model_name}...")
        self.model = SentenceTransformer(self.model_name)
        self.vector_dim = self.model.get_sentence_embedding_dimension()
        print(f"Model loaded successfully. Vector dimension: {self.vector_dim}")

    def embed_text(self, text: Union[str, List[str]]) -> np.ndarray:
        """Generates normalized vector embeddings for single strings or batch lists."""
        if isinstance(text, str):
            text = [text]
        embeddings = self.model.encode(text, normalize_embeddings=True)
        return embeddings

if __name__ == "__main__":
    encoder = EmbeddingEncoder()
    test_phrase = "Adversary abusing compromised credentials via technique T1078."
    vector = encoder.embed_text(test_phrase)
    print(f"Test embedding shape: {vector.shape}")