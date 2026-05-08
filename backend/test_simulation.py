import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from analyzer import (
    sanitize_input,
    extract_signals,
    calculate_technical_score,
    calculate_confidence,
    build_risk_factors,
    calculate_final_score,
    get_what_to_do,
)

# ---------------------------------------------------------------------------
# Simulated phishing email
# ---------------------------------------------------------------------------
emails_to_test = [
  {
    "label": "PayPal IL - account closure notice",
    "sender":  "service@paypal.co.il",
    "subject": "חשבון ה-PayPal שלך ייסגר",
    "body": (
        "שלום, Omer Reifenberg\n"
        "חשבון ה-PayPal שלך ייסגר בעוד 45 ימים.\n"
        "שמנו לב שלא נכנסת לחשבון ה-PayPal שלך יותר משלוש שנים. "
        "מטעמי אבטחה וכדי לעמוד בכל הדרישות, הגבלנו את חשבונך והוא ייסגר בעוד 45 ימים.\n"
        "יצירת חשבון חדש: https://www.paypal.com/il/signup/"
    ),
    "html_body": (
        '<h4 style="display:none;color:#F5F7FA;font-size:0px">Omer Reifenberg, להלן הפרטים.</h4>'
        "<p>חשבון ה-PayPal שלך ייסגר בעוד 45 ימים.</p>"
    ),
    "has_attachments": False,
    "headers": {
        "Authentication-Results": (
            "mx.google.com; "
            "dkim=pass header.i=@paypal.co.il; "
            "spf=pass smtp.mailfrom=service@paypal.co.il; "
            "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=paypal.co.il"
        ),
        "Received-SPF": "pass",
    },
  },
  {
    "label": "Olive Young - terms amendment notice",
    "sender":  "service_at_oliveyoung_com@privaterelay.appleid.com",
    "subject": "[Notice] Amendment of Terms & Policies - Effective May 26, 2026(KST)",
    "body": (
        "Hello, this is OLIVE YOUNG GLOBAL.\n"
        "Thank you for shopping with us.\n"
        "In order to provide better services, we would like to inform you that our "
        "Terms & Conditions, Privacy Policy, and Membership Policy will be revised "
        "in preparation for the launch of the US-dedicated platform (OLIVE YOUNG US).\n"
        "Please review the following changes to ensure your continued use of our services.\n"
        "Effective Date: May 26, 2026 (KST)\n"
        "Thank you."
    ),
    "html_body": "",
    "has_attachments": False,
    "headers": {
        "Authentication-Results": (
            "mx.google.com; "
            "dkim=pass header.i=@privaterelay.appleid.com; "
            "spf=pass smtp.mailfrom=privaterelay.bounce.t99rmcxcbn@privaterelay.appleid.com; "
            "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=appleid.com"
        ),
        "Received-SPF": "pass",
        "Reply-To": "noreply_at_oliveyoung_com@privaterelay.appleid.com",
    },
  },
]

for fake_email in emails_to_test:
  print(f"\n{'='*60}")
  print(f"  EMAIL: {fake_email['label']}")
  print(f"{'='*60}")

  email          = sanitize_input(fake_email)
  signals        = extract_signals(email)
  tech_score     = calculate_technical_score(signals)
  confidence, dots = calculate_confidence(signals)
  risk_factors   = build_risk_factors(signals)
  final_score, verdict = calculate_final_score(tech_score, ai_score=None)
  what_to_do     = get_what_to_do(verdict)

  print(f"  VERDICT:         {verdict}")
  print(f"  FINAL SCORE:     {final_score} / 100")
  print(f"  TECHNICAL SCORE: {tech_score} / 100")
  print(f"  CONFIDENCE:      {confidence}")
  print()

  print("  WHY:")
  for factor in risk_factors:
      print(f"    - {factor}")
  if not risk_factors:
      print("    (no risk factors)")

  print(f"\n  WHAT TO DO: {what_to_do}")

  print("\n  ALL SIGNALS:")
  for s in signals:
      status = "TRIGGERED" if s.triggered else ("skipped  " if not s.checked else "passed   ")
      print(f"    [{status}] {s.name:<22} weight={s.weight}")

exit()

fake_email = {
    "sender":  "service@paypal.co.il",
    "subject": "חשבון ה-PayPal שלך ייסגר",
    "body": (
        "שלום, Omer Reifenberg\n"
        "חשבון ה-PayPal שלך ייסגר בעוד 45 ימים.\n"
        "שמנו לב שלא נכנסת לחשבון ה-PayPal שלך יותר משלוש שנים. "
        "מטעמי אבטחה וכדי לעמוד בכל הדרישות, הגבלנו את חשבונך והוא ייסגר בעוד 45 ימים. "
        "לא תהיה לך יותר אפשרות לבצע עסקאות בחשבון זה, אבל ניתן יהיה להיכנס לחשבון לפני שהוא ייסגר "
        "כדי להציג את היסטוריית העסקאות.\n"
        "יצירת חשבון חדש: https://www.paypal.com/il/signup/"
    ),
    "html_body": (
        '<h4 style="display:none;color:#F5F7FA;font-size:0px">Omer Reifenberg, להלן הפרטים.</h4>'
        "<p>חשבון ה-PayPal שלך ייסגר בעוד 45 ימים.</p>"
    ),
    "has_attachments": False,
    "headers": {
        "Authentication-Results": (
            "mx.google.com; "
            "dkim=pass header.i=@paypal.co.il; "
            "spf=pass smtp.mailfrom=service@paypal.co.il; "
            "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=paypal.co.il"
        ),
        "Received-SPF": "pass (google.com: domain of service@paypal.co.il designates 173.0.84.3 as permitted sender)",
    },
}

# ---------------------------------------------------------------------------
# Run pipeline
# ---------------------------------------------------------------------------
email          = sanitize_input(fake_email)
signals        = extract_signals(email)
tech_score     = calculate_technical_score(signals)
confidence, dots = calculate_confidence(signals)
risk_factors   = build_risk_factors(signals)
final_score, verdict = calculate_final_score(tech_score, ai_score=None)
what_to_do     = get_what_to_do(verdict)

# ---------------------------------------------------------------------------
# Print results
# ---------------------------------------------------------------------------
print("\n" + "="*50)
print(f"  VERDICT:         {verdict}")
print(f"  FINAL SCORE:     {final_score} / 100")
print(f"  TECHNICAL SCORE: {tech_score} / 100")
print(f"  CONFIDENCE:      {confidence}")
print("="*50)

print("\nWHY:")
for factor in risk_factors:
    print(f"  • {factor}")

print(f"\nWHAT TO DO:\n  {what_to_do}")

print("\nALL SIGNALS:")
for s in signals:
    status = "TRIGGERED" if s.triggered else ("skipped  " if not s.checked else "passed   ")
    print(f"  [{status}] {s.name:<22} weight={s.weight}")

print()
