"""
ThreadLens - URL Intelligence MongoDB Atlas Batch Sync and Verification
Analyzes all stored email links and commits structured urlIntelligence directly to Atlas.
"""

import os
from pprint import pprint
from dotenv import load_dotenv
from pymongo import MongoClient

from url_intelligence import analyze_urls

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "YOUR_URI_HERE")
DB_NAME = "threadLens"
COLLECTION_NAME = "emails"


def sync_urls_to_mongo():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    docs = list(collection.find({}))
    total_docs = len(docs)
    print(f"Found {total_docs} documents in {DB_NAME}.{COLLECTION_NAME}. Starting sync...\n")

    updated_count = 0
    flagged_emails = 0

    for i, doc in enumerate(docs, 1):
        doc_id = doc["_id"]
        sender = doc.get("headers", {}).get("from", "")
        subject = doc.get("headers", {}).get("subject", "(No Subject)")
        raw_links = doc.get("links", [])

        # Run URL Intelligence analysis
        url_report = analyze_urls(raw_links, sender_email=sender)

        # Update document in-place on MongoDB Atlas
        collection.update_one(
            {"_id": doc_id},
            {"$set": {"urlIntelligence": url_report}}
        )
        updated_count += 1

        summary = url_report["summary"]
        status = summary["overall_status"]
        if status in ["MEDIUM", "HIGH", "CRITICAL"]:
            flagged_emails += 1

        print(f"[{i}/{total_docs}] Updated {doc_id} | Links: {len(raw_links)} | Status: {status} | Subject: {subject[:45]}")

    print(f"\n{'='*70}")
    print(f"[+] Successfully enriched {updated_count}/{total_docs} documents with 'urlIntelligence'.")
    print(f"[+] Total emails with MEDIUM/HIGH/CRITICAL links: {flagged_emails}")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    sync_urls_to_mongo()