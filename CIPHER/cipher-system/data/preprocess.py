import json
import os
import random

ENRON_DEPARTMENTS = ["trading", "legal", "compliance", "accounting", "hr", "operations", "facilities"]
ENRON_DOMAINS = ["enron.com", "ect.enron.com", "enronXgate.enron.com", "corporate.enron.net"]

BENIGN_TOPICS = [
    ("Gas Daily & Power Curves Update", "Attached are the daily trading volumes and price settlement indices for the Western desk. Please review the exposure summary before market close."),
    ("Master Netting Agreement Review", "The legal team has finalized the draft agreement with California power authorities. Redlined changes are tracked in Section 4.2."),
    ("FERC Compliance & Audit Filing", "Please ensure all transaction timestamps for Q3 are archived in compliance with the Federal Energy Regulatory Commission guidelines."),
    ("Weekly Trading Desk Risk Exposure", "Value at Risk (VaR) calculation models have been updated. Mark-to-market positions reflect current pipeline capacity limits."),
    ("Corporate Benefits & 401(k) Allocation", "Human Resources annual enrollment notice. Log in to the internal employee intranet to adjust your retirement contribution portfolio."),
    ("Quarterly Financial Consolidation Memo", "The financial reporting team is closing ledgers for the upcoming quarterly earnings release. Reconcile inter-company transfer logs."),
    ("IT Infrastructure Maintenance: Exchange Server 5.5", "Corporate IT will perform planned index optimization on the central mailbox database this Saturday from 02:00 to 06:00 CST.")
]

PHISH_LURES = [
    ("CRITICAL: Microsoft 365 Password Expires In 2 Hours", "Your corporate Microsoft account credentials have expired. Immediate re-authentication required: http://194.135.22.14/login to prevent Active Directory revocation.", "admin@micr0soft-portal-update.ru", "micr0soft", "microsoft.com"),
    ("ACTION REQUIRED: Multi-Factor Authentication Migration", "Corporate identity migration to Azure Authenticator is mandatory. Verify your mobile security certificate immediately at http://45.33.32.156/auth", "it-support@bennett-support.xyz", "bennett-support", "bennett.edu.in"),
    ("Urgent Wire Transfer & Salary Slip Approval", "Kindly review and authorize the attached executive payroll adjustment structure. Confirm wire transfer details via: https://bit.ly/secure-pay-slip", "payroll@wire-transfer-desk.xyz", "wire-transfer", "enron.com"),
    ("Quishing Security Notice: Update Authenticator Token", "Per security compliance, please scan the QR code embedded in the secure attachment using your mobile camera to refresh your 2FA token.", "sec-ops@security-token-update.click", "security-token", "office.com")
]

print("Building 5,000 Enterprise Corpus (Enron + Real Threat Vectors)...")

emails = []
for i in range(1, 5001):
    if i <= 500:
        subj, body, sender, lookalike, brand = random.choice(PHISH_LURES)
        emails.append({
            "id": 1000 + i,
            "sender": sender,
            "subject": f"{subj} [Ref-{1000+i}]",
            "body": f"{body} (Case ID: {random.randint(10000, 99999)})",
            "status": "pending",
            "threat_type": "phishing",
            "homoglyph_detected": lookalike,
            "target_brand": brand
        })
    else:
        subj, body = random.choice(BENIGN_TOPICS)
        user = f"user.{random.randint(10, 999)}"
        dept = random.choice(ENRON_DEPARTMENTS)
        domain = random.choice(ENRON_DOMAINS)
        sender = f"{user}.{dept}@{domain}"
        
        emails.append({
            "id": 1000 + i,
            "sender": sender,
            "subject": f"{subj} - Thread {random.randint(200, 900)}",
            "body": f"{body} Regards, {user.replace('.', ' ').title()}, Enron {dept.title()} Operations.",
            "status": "pending",
            "threat_type": "safe",
            "homoglyph_detected": None,
            "target_brand": None
        })

random.shuffle(emails)

output_file = os.path.join(os.path.dirname(__file__), "..", "test_samples", "mock_threats.json")
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(emails, f, indent=2)

print(f"SUCCESS! {len(emails)} emails generated directly in {output_file}")