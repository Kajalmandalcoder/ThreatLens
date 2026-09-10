import os
import sys
import pprint
import traceback
from pymongo import MongoClient
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
sys.path.insert(0, PROJECT_ROOT)

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
load_dotenv(os.path.join(PROJECT_ROOT, "backend", ".env"))

from backend.services.image_intelligence import analyze_email_image_intelligence

def test_mongo_image_intelligence():
    mongo_uri = os.getenv("MONGO_URI") or "mongodb+srv://admin_user:Adminpass123@cluster0.da8l5ie.mongodb.net/?appName=Cluster0"
    db_name = os.getenv("DB_NAME") or "threadLens"

    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=8000)
    db = client[db_name]
    collection = db["emails"]

    # Ek real case uthao jisme HTML body ho
    doc = collection.find_one({"caseId": "CASE-2026-A2C7E0"})
    if not doc:
        print("[!] Document not found")
        return

    print(f"[+] Case ID: {doc.get('caseId')}")
    print(f"[+] Sender : {doc.get('headers', {}).get('from')}")

    # Standard email message create karo body ke saath
    msg = MIMEMultipart()
    msg["Subject"] = str(doc.get("headers", {}).get("subject", ""))
    msg["From"] = str(doc.get("headers", {}).get("from", ""))
    msg["To"] = str(doc.get("headers", {}).get("to", ""))
    
    html_content = doc.get("body", {}).get("html", "") or "<p>No body</p>"
    msg.attach(MIMEText(html_content, "html"))

    sender = doc.get("headers", {}).get("from", "")

    print("\n--- Running Image Intelligence Module ---")
    results = analyze_email_image_intelligence(msg, sender_email=sender)
    pprint.pprint(results)

if __name__ == "__main__":
    test_mongo_image_intelligence()