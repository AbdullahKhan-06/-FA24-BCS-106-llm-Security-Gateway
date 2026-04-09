INJECTION_THRESHOLD = 4
PII_THRESHOLD = 1

def decide_policy(injection_score, pii_results):
    if injection_score >= INJECTION_THRESHOLD:
        return "BLOCK"

    elif len(pii_results) >= PII_THRESHOLD:
        return "MASK"

    else:
        return "ALLOW"