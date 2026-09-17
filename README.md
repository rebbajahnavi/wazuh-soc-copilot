\# Wazuh Security Event Response with RAG-Driven Copilot



An AI-powered Security Operations Center (SOC) Copilot designed to analyze Wazuh security event alerts, ground incident context using Retrieval-Augmented Generation (RAG) across NIST CSF 2.0 and MITRE ATT\&CK knowledge bases, and deliver structured incident mitigation guidance.



\## Architecture Highlights

\- \*\*SIEM:\*\* Wazuh (Event capture \& JSON alert generation)

\- \*\*Vector Database:\*\* Qdrant

\- \*\*Embedding Model:\*\* BAAI/bge-large-en-v1.5

\- \*\*Knowledge Sources:\*\* General Incident Response Guides, NIST CSF 2.0, MITRE ATT\&CK

