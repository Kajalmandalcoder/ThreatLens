import sys
import os
import json
from email import policy
from email.parser import BytesParser
from contextlib import redirect_stdout

# ============================================================
# PROJECT ROOT PATH
# ============================================================

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)

# Allow Python to import root-level modules:
# image_intelligence
# url_intelligence
# intelligence
# ml_model
sys.path.insert(0, PROJECT_ROOT)

# ============================================================
# IMAGE INTELLIGENCE IMPORT
# ============================================================

from image_intelligence import analyze_email_image_intelligence


def main():

    if len(sys.argv) < 2:
        print(json.dumps({
            "success": False,
            "message": "EML path required"
        }))
        return

    eml_path = sys.argv[1]

    try:

        # ----------------------------------------------------
        # Read EML
        # ----------------------------------------------------

        with open(eml_path, "rb") as f:
            msg = BytesParser(
                policy=policy.default
            ).parse(f)

        # ----------------------------------------------------
        # Sender
        # ----------------------------------------------------

        sender_email = msg.get("From")

        # ----------------------------------------------------
        # Run Image Intelligence
        # ----------------------------------------------------
        # Library logs (EasyOCR etc.) go to stderr.
        # stdout remains clean JSON for Node.js.

        with redirect_stdout(sys.stderr):

            result = analyze_email_image_intelligence(
                msg,
                sender_email=sender_email
            )

        # ----------------------------------------------------
        # Return JSON
        # ----------------------------------------------------

        print(json.dumps({
            "success": True,
            "imageIntelligence": result
        }))

    except Exception as e:

        print(json.dumps({
            "success": False,
            "message": str(e)
        }))


if __name__ == "__main__":
    main()