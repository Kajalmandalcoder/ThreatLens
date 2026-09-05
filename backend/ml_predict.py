import sys
import json
import os
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml_model"
)


def main():

    if len(sys.argv) < 2:
        print(json.dumps({
            "success": False,
            "error": "No email text provided"
        }))
        sys.exit(1)

    email_text = sys.argv[1]

    try:

        tokenizer = AutoTokenizer.from_pretrained(
            MODEL_PATH,
            local_files_only=True
        )

        model = AutoModelForSequenceClassification.from_pretrained(
            MODEL_PATH,
            local_files_only=True
        )

        classifier = pipeline(
            "text-classification",
            model=model,
            tokenizer=tokenizer
        )

        result = classifier(
            email_text,
            truncation=True
        )[0]

        label = result["label"]

        confidence = round(
            float(result["score"]) * 100,
            2
        )

        if label == "LABEL_1":
            prediction = "THREAT"
        else:
            prediction = "SAFE"

        print(json.dumps({
            "success": True,
            "prediction": prediction,
            "confidence": confidence,
            "raw_label": label
        }))

    except Exception as error:

        print(json.dumps({
            "success": False,
            "error": str(error)
        }))

        sys.exit(1)


if __name__ == "__main__":
    main()