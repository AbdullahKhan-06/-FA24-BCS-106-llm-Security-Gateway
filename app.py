from fastapi import FastAPI
from pydantic import BaseModel
import time
import csv
import os

from injection_detector import detect_injection
from pii_utlis import analyze_pii, anonymize_text
from policy import decide_policy

app = FastAPI(title="LLM Security Gateway", version="2.0")

class UserInput(BaseModel):
    text: str

# 🔹 Define CSV file path (absolute path)
CSV_FILE = os.path.join(os.getcwd(), "evaluation_log.csv")

# 🔹 Create file with header if it does not exist
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Input Text",
            "Decision",
            "Injection Score",
            "PII Count",
            "Latency",
            "Risk Level"
        ])
    print("✅ CSV file created at:", CSV_FILE)


@app.post("/process")
def process_input(user_input: UserInput):
    start_time = time.time()

    text = user_input.text

    # 🔹 Step 1: Injection Detection
    injection_score, matches = detect_injection(text)

    # 🔹 Step 2: PII Detection
    pii_results = analyze_pii(text)

    # 🔹 Step 3: Policy Decision
    decision = decide_policy(injection_score, pii_results)

    # 🔹 Step 4: Output Handling
    if decision == "BLOCK":
        output = "⚠️ Request blocked due to suspected prompt injection attack."

    elif decision == "MASK":
        output = anonymize_text(text, pii_results)

    else:
        output = text

    # 🔹 Latency Calculation
    latency = round(time.time() - start_time, 4)

    # 🔹 Risk Level
    if injection_score >= 4:
        risk_level = "HIGH"
    elif injection_score >= 2:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # 🔹 Save Results to CSV
    try:
        with open(CSV_FILE, mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                text,
                decision,
                injection_score,
                len(pii_results),
                latency,
                risk_level
            ])
        print("✅ Data written to CSV")
    except Exception as e:
        print("❌ Error writing CSV:", e)

    return {
        "decision": decision,
        "original_text": text,
        "processed_output": output,
        "injection_score": injection_score,
        "matched_patterns": matches,
        "pii_entities_detected": len(pii_results),
        "risk_level": risk_level,
        "latency_seconds": latency
    }