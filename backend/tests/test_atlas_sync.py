"""
ThreadLens - Batch Enriches All Documents in MongoDB Atlas
"""

import os
from pprint import pprint
from dotenv import load_dotenv
from pymongo import MongoClient
from intelligence import process_intelligence_pipeline

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "YOUR_URI_HERE")
DB_NAME = "threadLens"
COLLECTION_NAME = "emails"


def run_batch_enrichment():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    docs = list(collection.find({}))
    total = len(docs)
    print(f"Found {total} documents in {DB_NAME}.{COLLECTION_NAME}. Processing...")

    updated_count = 0
    for doc in docs:
        doc_id = doc["_id"]
        subject = doc.get("headers", {}).get("subject", "No Subject")
        
        intel_output = process_intelligence_pipeline(doc, offline_mode=False)

        collection.update_one(
            {"_id": doc_id},
            {
                "$set": {
                    "ipIntelligence": intel_output["ip_intelligence"],
                    "domainIntelligence": intel_output["domain_intelligence"],
                    "intelligenceSignals": intel_output["intelligence_signals"],
                }
            },
        )
        updated_count += 1
        print(f"[{updated_count}/{total}] Enriched doc: {doc_id} | Subject: {subject}")

    print(f"\n[+] Finished! Successfully enriched {updated_count} documents in MongoDB Atlas.")


if __name__ == "__main__":
    run_batch_enrichment()