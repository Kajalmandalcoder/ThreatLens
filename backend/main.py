import json
import os
import glob
from email import policy
from email.parser import BytesParser
from header_forensics import HeaderForensicsEngine

# Automatically detect all .eml files inside the 'emails' folder
eml_files = sorted(glob.glob("emails/*.eml"))

if not eml_files:
    print("❌ No .eml files found in 'emails/' directory!")
else:
    print(f"📁 Found {len(eml_files)} file(s) to test: {eml_files}\n")

for file_path in eml_files:
    print(f"============================================")
    print(f" 🔍 TESTING FILE: {file_path}")
    print(f"============================================")
    
    try:
        with open(file_path, "rb") as f:
            parsed_msg = BytesParser(policy=policy.default).parse(f)

        # Run Akankcha's Header Forensics Module
        engine = HeaderForensicsEngine(parsed_msg)
        output = engine.generate_header_findings()

        print(json.dumps(output, indent=4))
        print("\n")
        
    except Exception as e:
        print(f"❌ Error processing {file_path}: {e}\n")