import json
import numpy as np
import faiss
from attackcti import attack_client
from sentence_transformers import SentenceTransformer

print("Fetching MITRE data...")

lift = attack_client()
techniques = lift.get_techniques()

mitre_data = []

for t in techniques:
    try:
        name = t.get("name", "")
        description = t.get("description", "")

        for ref in t.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id")

                mitre_data.append({
                    "name": name,
                    "description": description,
                    "mitre_id": mitre_id
                })
    except:
        continue

print(f"Collected {len(mitre_data)} techniques")

# -------------------------------
# EMBEDDINGS
# -------------------------------
print("Loading embedding model...")
embedder = SentenceTransformer("all-MiniLM-L6-v2")

documents = [item["description"] for item in mitre_data]

print("Generating embeddings...")
embeddings = embedder.encode(documents)

# -------------------------------
# FAISS INDEX
# -------------------------------
dimension = embeddings.shape[1]
index = faiss.IndexFlatL2(dimension)
index.add(np.array(embeddings))

# -------------------------------
# SAVE FILES
# -------------------------------
print("Saving files...")

faiss.write_index(index, "mitre_index.faiss")

with open("mitre_data.json", "w") as f:
    json.dump(mitre_data, f)

print("✅ Done! Files saved:")
print("- mitre_index.faiss")
print("- mitre_data.json")