import re

# weighted suspicious patterns
patterns = {
    r"ignore\s+previous\s+instructions": 3,
    r"bypass": 2,
    r"jailbreak": 3,
    r"system\s+prompt": 3,
    r"reveal\s+secret": 2,
    r"override": 2,
    r"act\s+as\s+admin": 3
}

def detect_injection(user_input):
    score = 0
    matches = []

    for pattern, weight in patterns.items():
        if re.search(pattern, user_input, re.IGNORECASE):
            score += weight
            matches.append(pattern)

    # bonus: long suspicious input
    if len(user_input.split()) > 30:
        score += 1

    return score, matches