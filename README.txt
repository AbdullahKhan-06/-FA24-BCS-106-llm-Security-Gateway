# LLM Security Gateway

 Overview

This project implements a security gateway for LLM inputs using FastAPI.
It detects prompt injection attacks and sensitive information (PII) using Presidio.

 Features

* Prompt injection detection
* PII detection (API keys, Pakistani phone numbers)
* Custom masking logic
* Policy-based decision system (ALLOW, MASK, BLOCK)
* Latency measurement

Technologies Used

* Python
* FastAPI
* Microsoft Presidio

 How to Run

```bash
uvicorn app:app --reload
```

Then open:
http://127.0.0.1:8000/docs

 Example Input

```json
{
  "text": "My number is 03015540952"
}
```

 Output

* Detects sensitive data
* Masks phone numbers
* Returns decision and latency
