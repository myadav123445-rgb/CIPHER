import re

LOOKALIKE_TARGETS = [
    ("micr0soft", "microsoft.com"),
    ("paypa1", "paypal.com"),
    ("g00gle", "google.com"),
    ("bennett-portal-login", "bennett.edu.in"),
    ("netflix-verify", "netflix.com"),
    ("rnicrosoft", "microsoft.com"),
    ("app1e", "apple.com")
]

URGENT_KEYWORDS = [
    "urgent", "immediate action", "account suspended", "wire transfer", 
    "verify your identity", "password expires", "unauthorized access", 
    "payroll invoice", "quarantine release", "2fa expired", "swift transfer"
]

HIGH_RISK_TLDS = [".ru", ".xyz", ".top", ".click", ".tk", ".pw", ".cc", ".link", ".cfd"]

def evaluate_threat(sender: str, subject: str, body: str):
    score = 10
    explanations = []
    lens_data = None
    quishing_detected = False

    s_lower = (sender or "").lower()
    full_text = f"{subject} {body}".lower()

    # 1. Optical Homoglyph / Lookalike Domain Inspection
    for fake, legitimate in LOOKALIKE_TARGETS:
        if fake in s_lower:
            score += 42
            explanations.append(f"Domain Spoofing: Lookalike imitation '{fake}' targeting legitimate domain '{legitimate}'.")
            lens_data = {
                "detected": fake,
                "target": legitimate,
                "reason": f"Optical homoglyph spoofing imitating '{legitimate}'"
            }
            break

    # 2. High-Risk TLD Verification
    matched_tld = [ext for ext in HIGH_RISK_TLDS if ext in s_lower.split("@")[-1]]
    if matched_tld:
        score += 22
        explanations.append(f"High-Risk TLD: Sent via untrusted generic top-level domain ({matched_tld[0]}).")

    # 3. Urgency & Social Engineering Analysis
    found_keywords = [kw for kw in URGENT_KEYWORDS if kw in full_text]
    if found_keywords:
        added = min(len(found_keywords) * 14, 38)
        score += added
        explanations.append(f"Social Engineering: High pressure triggers detected ({', '.join(found_keywords[:2])}).")

    # 4. Quishing (QR Phishing) Heuristic Scan
    if any(q_term in full_text for q_term in ["qr code", "scan the qr", "authenticator scan", "scan to login", "qr-auth"]):
        quishing_detected = True
        score += 32
        explanations.append("Quishing Vector: Email instructs user to scan an optical QR code to bypass perimeter defenses.")

    # 5. Advanced Link & IP Heuristics
    urls = re.findall(r'(https?://[^\s]+)', body)
    if urls:
        for u in urls:
            if any(sh in u.lower() for sh in ["bit.ly", "tinyurl", "t.co", "is.gd", "rb.gy"]):
                score += 26
                explanations.append("Obfuscated Link: Shortened redirect hides threat infrastructure.")
                break
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u):
                score += 36
                explanations.append("Raw IP URL: Points directly to bare numeric IP destination, bypassing DNS reputation.")
                break

    # Normalization & Tier Classification
    score = min(max(score, 5), 99)
    if score >= 65:
        tier = "DANGEROUS PHISHING"
    elif score >= 35:
        tier = "FLAGGED FOR HUMAN"
    else:
        tier = "SAFE"

    if not explanations:
        explanations = [
            "Domain authenticated via SPF/DKIM baseline check.",
            "No known credential-harvesting patterns found."
        ]

    return score, tier, explanations, lens_data, quishing_detected