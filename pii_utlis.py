from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine


analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()


api_key_pattern = Pattern(
    name="api_key_pattern",
    regex=r"sk-[A-Za-z0-9]{20,}",
    score=0.9
)

api_key_recognizer = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[api_key_pattern]
)

analyzer.registry.add_recognizer(api_key_recognizer)


phone_pattern = Pattern(
    name="pk_phone",
    regex=r"03[0-9]{9}",
    score=0.85
)

phone_recognizer = PatternRecognizer(
    supported_entity="PK_PHONE",
    patterns=[phone_pattern]
)

analyzer.registry.add_recognizer(phone_recognizer)


def analyze_pii(text):
    results = analyzer.analyze(text=text, language='en')

    # 🔹 Confidence filtering (customization)
    filtered_results = [res for res in results if res.score > 0.5]

    return filtered_results


def anonymize_text(text, results):
    # Custom masking logic
    masked_text = text

    for res in results:
        if res.entity_type == "PK_PHONE":
            original = text[res.start:res.end]
            masked = original[:2] + "*" * (len(original) - 2)
            masked_text = masked_text.replace(original, masked)

    return masked_text