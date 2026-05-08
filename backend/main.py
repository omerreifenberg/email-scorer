import os
import logging
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from analyzer import (
    sanitize_input,
    extract_signals,
    calculate_technical_score,
    calculate_confidence,
    build_risk_factors,
    calculate_final_score,
    get_what_to_do,
    analyze_with_ai,
    analyze_with_openai,
)

# Load secrets from .env file
load_dotenv()

# Logger — we use this instead of print() so we control what gets logged
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# The secret key the Add-on must send with every request
API_KEY = os.getenv("SCORER_API_KEY")

# Create the FastAPI app
app = FastAPI(title="Email Maliciousness Scorer", version="1.0.0")

# ---------------------------------------------------------------------------
# REQUEST MODEL
# Defines exactly what the Add-on must send us.
# Pydantic validates this automatically — if a field is missing or wrong
# type, FastAPI returns a 422 error before our code even runs.
# ---------------------------------------------------------------------------
class EmailRequest(BaseModel):
    sender:          str
    subject:         str
    body:            str
    html_body:       str  = ""
    has_attachments: bool = False
    headers:         dict = {}

# ---------------------------------------------------------------------------
# RESPONSE MODEL
# Defines exactly what we send back to the Add-on.
# ---------------------------------------------------------------------------
class AnalysisResponse(BaseModel):
    final_score:     int
    verdict:         str
    technical_score: int
    ai_score:        int | None
    confidence:      str
    confidence_dots: str
    risk_factors:    list[str]
    reasoning:       str
    what_to_do:      str

# CORS — allows the Gmail Add-on (running on Google's servers) to talk to our backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# HEALTH CHECK
# A simple endpoint to confirm the server is running.
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# MAIN ENDPOINT — /analyze
# Receives email data from the Gmail Add-on and returns a full analysis.
# ---------------------------------------------------------------------------
@app.post("/analyze", response_model=AnalysisResponse)
def analyze(payload: EmailRequest, x_api_key: str = Header(None)):

    # Step 1 — Authenticate the request
    if API_KEY and x_api_key != API_KEY:
        logger.warning("Rejected request with invalid API key")
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Step 2 — Sanitize: enforce input limits before doing anything
    email = sanitize_input(payload.model_dump())

    # Log only metadata — never log email content
    logger.info(
        f"Analyzing email | sender_domain={email['sender'].split('@')[-1]} "
        f"| subject_length={len(email['subject'])} "
        f"| body_length={len(email['body'])}"
    )

    try:
        # Step 3 — Run all signal checks
        signals = extract_signals(email)

        # Step 4 — Calculate technical score from signals
        technical_score = calculate_technical_score(signals)

        # Step 5 — Run both AI models independently
        claude_result = analyze_with_ai(email)
        openai_result = analyze_with_openai(email)

        # Step 6 — Combine AI scores
        # Both available  → average of both scores
        # Only one        → use that one
        # Neither         → None (technical score only)
        if claude_result and openai_result:
            ai_score        = round((claude_result["ai_score"] + openai_result["ai_score"]) / 2)
            reasoning       = claude_result["reasoning"]
            ai_risk_indicators = claude_result.get("risk_indicators", [])
            logger.info(
                f"AI scores — Claude: {claude_result['ai_score']} | "
                f"OpenAI: {openai_result['ai_score']} | "
                f"Average: {ai_score}"
            )
        elif claude_result:
            ai_score           = claude_result["ai_score"]
            reasoning          = claude_result["reasoning"]
            ai_risk_indicators = claude_result.get("risk_indicators", [])
        elif openai_result:
            ai_score           = openai_result["ai_score"]
            reasoning          = openai_result["reasoning"]
            ai_risk_indicators = openai_result.get("risk_indicators", [])
        else:
            ai_score           = None
            reasoning          = "AI analysis was not available."
            ai_risk_indicators = []

        # Step 7 — Combine scores into final result
        final_score, verdict = calculate_final_score(technical_score, ai_score)

        # Step 8 — Build human-readable output
        confidence, confidence_dots = calculate_confidence(signals)
        risk_factors                = build_risk_factors(signals, ai_risk_indicators)
        what_to_do                  = get_what_to_do(verdict)

    except Exception as e:
        logger.error(f"Analysis pipeline failed: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="Analysis failed. Please try again.")

    return AnalysisResponse(
        final_score     = final_score,
        verdict         = verdict,
        technical_score = technical_score,
        ai_score        = ai_score,
        confidence      = confidence,
        confidence_dots = confidence_dots,
        risk_factors    = risk_factors,
        reasoning       = reasoning,
        what_to_do      = what_to_do,
    )
