# Email Scorer — Gmail Add-on

A Gmail Add-on that analyzes every email you open and instantly tells you whether it is **Safe**, **Suspicious**, or **Malicious** — with a plain-language explanation of why.

---

## What It Does

When you open an email in Gmail, the add-on panel automatically:

1. Extracts the email's metadata, headers, body, and links
2. Sends them to a backend service for analysis
3. Displays a verdict, a risk score (0–100), a confidence level, and up to four specific findings that explain the result

The result looks like this:

| Field | Example |
|---|---|
| Verdict | 🚨 Malicious |
| Risk Score | 67 / 100 |
| Confidence | High ●●●● |
| Finding 1 | Replies go to 'apple-verify.net', not to the sender 'gmail.com' |
| Finding 2 | Sender claims to be 'Apple Support' but the email actually comes from 'gmail.com' |
| Finding 3 | 4 suspicious links: contains an unsecured (HTTP) link |
| Action | Do not click any links or reply to this email. Delete it immediately. |

---

## Architecture

```
Gmail (browser)
    │
    │  onGmailMessage()
    ▼
Google Apps Script (Code.gs)
    │  POST /analyze
    │  { sender, subject, body, html_body, headers, has_attachments }
    ▼
FastAPI Backend (Python, deployed on Render)
    │
    ├── sanitize_input()          — enforce input size limits
    ├── extract_signals()         — 11 weighted signals + real-time URLhaus check
    ├── calculate_technical_score()
    ├── analyze_with_ai()         — Claude claude-3-5-haiku-20241022
    ├── analyze_with_openai()     — GPT-4o (cross-validation)
    ├── calculate_final_score()   — 60% technical + 40% AI
    └── build_risk_factors()      — plain-language findings for the UI
```

The add-on is deliberately thin — it reads the email and renders the result. All analysis logic lives in the backend, which makes it easy to update, test, and extend without touching the Apps Script deployment.

---

## How the Score Works

### Step 1 — Technical Signals (11 weighted checks)

Each check returns a `Signal` with a weight. If triggered, its weight is added to the technical score.

| Signal | Weight | What it detects |
|---|---|---|
| `display_name_spoofing` | 15 | Display name claims a known brand but sends from a different domain |
| `reply_to_mismatch` | 15 | Reply-To address differs from the sender's domain |
| `suspicious_links` | 13 | HTTP links, raw IPs, URL shorteners, or dangerous file extensions |
| `typosquatting` | 11 | Domain impersonates a known brand via lookalike characters or embedding |
| `domain_reputation` | 10 | Suspicious TLD, unusually long domain, excessive hyphens, or brand-as-subdomain |
| `spf` | 8 | SPF authentication failed |
| `dkim` | 8 | DKIM signature missing or invalid |
| `personal_info` | 6 | Email requests passwords, credit card numbers, or sensitive personal data |
| `dmarc` | 6 | No DMARC policy on sender domain |
| `hidden_text` | 5 | White-on-white or zero-size text (used to fool spam filters or AI) |
| `urgency` | 3 | Language designed to pressure the reader into acting immediately |
| **Total** | **100** | |

**Weight rationale:** Identity signals (`display_name_spoofing`, `reply_to_mismatch`) are weighted highest because they require deliberate intent to forge and directly indicate deception. Auth signals (SPF/DKIM/DMARC) are weighted lower because sophisticated phishing campaigns routinely pass all three by sending through legitimate infrastructure like Gmail or SendGrid.

`suspicious_links` uses dynamic scoring: each suspicious link contributes 2.5 points, capped at the signal's maximum weight (13). This rewards multiple red flags while preventing a single signal from dominating.

`has_attachments` is collected and sent to the backend but not yet scored — reserved for a future signal that combines attachment presence with other indicators (e.g. password-protected ZIP + urgency language).

### Step 2 — Real-Time URL Check (URLhaus)

Links in the email body are checked against [URLhaus](https://urlhaus.abuse.ch/) — a public database of known malicious URLs maintained by security researchers. To keep latency low, only the first 5 links are checked. If any link matches, the score is recalculated using `round(base × 0.69) + 31`, ensuring a minimum of 31 (Suspicious) while scaling other signals proportionally.

### Step 3 — Dual AI Analysis

The email content (not the technical signals) is independently analyzed by two models:

- **Claude** (`claude-haiku-4-5`) via Anthropic API
- **GPT-4o** via OpenAI API

Both models receive the same prompt and scoring guidelines. If both are available, their scores are averaged. If only one is available, that score is used. If neither is available, the final score falls back to the technical score alone — the system degrades gracefully.

Using two independent models reduces the risk of one model being manipulated by prompt injection content embedded in the email body.

### Step 4 — Final Score

```
final_score = round(technical_score × 0.6 + ai_score × 0.4)
```

| Range | Verdict |
|---|---|
| 0 – 30 | ✅ Safe |
| 31 – 59 | ⚠️ Suspicious |
| 60 – 100 | 🚨 Malicious |

The 60/40 split gives the technical score more weight while allowing AI analysis to meaningfully influence borderline cases. A purely rule-based score can miss context; a purely AI-based score can be manipulated by carefully crafted email content.

### Step 5 — Confidence

Confidence reflects how many checks could actually run. Some signals (SPF, DKIM, DMARC) require specific email headers that are not always present. Missing headers reduce confidence without affecting the verdict.

---

## Security Design

Security was treated as a first-class concern throughout.

**Untrusted input:**
- All email fields are truncated before processing (`MAX_BODY_LENGTH = 8,000` characters, etc.)
- The AI prompt explicitly labels email content as untrusted and instructs the model not to follow any instructions found inside it
- Both AI functions have independent try/except blocks — a manipulated email that causes one model to crash cannot affect the other or the overall pipeline

**Prompt injection protection:**
- The system prompt instructs the AI to treat the email as data, not instructions
- Hidden text (white-on-white, font-size:0) is explicitly flagged as a potential manipulation vector in the prompt
- The technical `hidden_text` signal independently detects and scores this technique

**API security:**
- The backend requires an `X-API-Key` header on every request
- API keys (Anthropic, OpenAI, backend key) are stored as environment variables — never in code (except for a simple demo key used by the Apps Script client)
- The `.env` file is listed in `.gitignore`

**Sensitive data:**
- The backend logs only metadata (sender domain, subject length, body length) — never email content
- Email content is never stored or persisted

---

## Project Structure

```
email-scorer/
├── addon/
│   ├── Code.gs                  # Google Apps Script — Gmail Add-on
│   └── appsscript.json          # Add-on manifest — permissions, triggers, metadata
├── backend/
│   ├── main.py                  # FastAPI app — request handling and pipeline orchestration
│   ├── analyzer.py              # All analysis logic — signals, scoring, AI calls
│   └── requirements.txt
└── README.md
```

---

## Setup

### Backend

The backend is a FastAPI app deployable to any Python host. It is currently running on [Render](https://render.com) (free tier).

**Requirements:** Python 3.11+

```bash
cd backend
pip install -r requirements.txt
```

Create a `.env` file:
```
ANTHROPIC_API_KEY=your_anthropic_key
OPENAI_API_KEY=your_openai_key
SCORER_API_KEY=your_secret_key
```

Run locally:
```bash
uvicorn main:app --reload
```

Health check: `GET /health` → `{"status": "ok"}`

### Gmail Add-on

1. Open [Google Apps Script](https://script.google.com) and create a new project
2. Paste the contents of `addon/Code.gs`
3. Set `BACKEND_URL` and `API_KEY` at the top of the file
4. Deploy as a Gmail Add-on (Extensions → Add-ons → Deploy)
5. Install the add-on on your Gmail account

