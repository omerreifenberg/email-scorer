// ---------------------------------------------------------------------------
// CONFIGURATION
// Replace these values before deploying.
// ---------------------------------------------------------------------------
var BACKEND_URL = "https://email-scorer.onrender.com/analyze";
var API_KEY     = "upwind123"; // Must match SCORER_API_KEY in .env


// ---------------------------------------------------------------------------
// ENTRY POINT
// Google calls this function automatically every time the user opens an email.
// ---------------------------------------------------------------------------
function onGmailMessage(e) {
  var accessToken = e.gmail.accessToken;
  var messageId   = e.gmail.messageId;

  // Give the add-on permission to read this specific email
  GmailApp.setCurrentMessageAccessToken(accessToken);

  var message = GmailApp.getMessageById(messageId);

  // Build the payload to send to our backend
  var payload = buildPayload(message);

  // Send to backend and get result
  var result = callBackend(payload);

  // If something went wrong, show an error card
  if (result.error) {
    return buildErrorCard(result.error);
  }

  // Otherwise show the analysis result
  return buildResultCard(result);
}


// ---------------------------------------------------------------------------
// BUILD PAYLOAD
// Reads the email and packages it into an object to send to our backend.
// We read only what we need — sender, subject, body, headers, attachments.
// ---------------------------------------------------------------------------
function buildPayload(message) {
  var headers = {};

  // These are the technical headers that contain SPF / DKIM / DMARC results
  var headersToRead = [
    "Authentication-Results",
    "Received-SPF",
    "Reply-To",
    "From",
  ];

  headersToRead.forEach(function(name) {
    var value = message.getHeader(name);
    if (value) {
      headers[name] = value;
    }
  });

  return {
    sender:          message.getFrom(),
    subject:         message.getSubject(),
    body:            message.getPlainBody(),
    html_body:       message.getBody(),
    has_attachments: message.getAttachments().length > 0,
    headers:         headers,
  };
}


// ---------------------------------------------------------------------------
// CALL BACKEND
// Sends the email payload to our Python server and returns the result.
// ---------------------------------------------------------------------------
function callBackend(payload) {
  var options = {
    method:             "post",
    contentType:        "application/json",
    payload:            JSON.stringify(payload),
    headers:            { "X-API-Key": API_KEY },
    muteHttpExceptions: true,  // Don't crash on HTTP errors — handle them ourselves
    deadline:           25,    // Timeout after 25 seconds — show error instead of freezing
  };

  try {
    var response = UrlFetchApp.fetch(BACKEND_URL, options);
    var code     = response.getResponseCode();

    if (code !== 200) {
      return { error: "Backend returned error: " + code };
    }

    return JSON.parse(response.getContentText());

  } catch (err) {
    return { error: "Could not reach backend: " + err.message };
  }
}


// ---------------------------------------------------------------------------
// BUILD RESULT CARD
// Builds the visual panel shown to the user in Gmail.
// Structure:
//   Header   : verdict icon + label
//   Subtitle : Risk Score + Confidence level
//   Section 1: 🔍 Analysis Findings — up to 4 signals (technical + AI)
//   Section 2: ✅ Recommended Action — one clear instruction
// ---------------------------------------------------------------------------
function buildResultCard(result) {
  var verdict        = result.verdict;
  var score          = result.final_score;
  var confidence     = result.confidence;
  var confidenceDots = result.confidence_dots;
  var riskFactors    = result.risk_factors || [];
  var whatToDo       = result.what_to_do   || "";

  // ── Header ───────────────────────────────────────────────────────────────
  var icon = verdict === "Safe" ? "✅" : verdict === "Suspicious" ? "⚠️" : "🚨";

  var header = CardService.newCardHeader()
    .setTitle(icon + "  " + verdict);

  // ── Score + Confidence as separate lines ─────────────────────────────────
  var scoreSection = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText("<font color='#444444'>Risk Score: </font><b>" + score + " / 100</b>")
    )
    .addWidget(
      CardService.newTextParagraph()
        .setText("<font color='#444444'>Confidence: " + confidence + "  " + confidenceDots + "</font>")
    );

  // ── Section 1: Analysis Summary ──────────────────────────────────────────
  var bullet = "•  ";

  var findingsSection = CardService.newCardSection()
    .setHeader("Analysis summary:");

  if (riskFactors.length === 0) {
    findingsSection.addWidget(
      CardService.newTextParagraph().setText("✔  No suspicious signals detected.")
    );
  } else {
    riskFactors.forEach(function(factor) {
      findingsSection.addWidget(
        CardService.newTextParagraph().setText(bullet + factor)
      );
    });
  }

  // ── Section 2: Recommended Action ────────────────────────────────────────
  var actionSection = CardService.newCardSection()
    .setHeader("✅ Recommended Action")
    .addWidget(
      CardService.newTextParagraph().setText("<b>" + whatToDo + "</b>")
    );

  // ── Assemble ──────────────────────────────────────────────────────────────
  return [
    CardService.newCardBuilder()
      .setHeader(header)
      .addSection(scoreSection)
      .addSection(findingsSection)
      .addSection(actionSection)
      .build()
  ];
}


// ---------------------------------------------------------------------------
// BUILD ERROR CARD
// Shown when the backend is unreachable or returns an error.
// ---------------------------------------------------------------------------
function buildErrorCard(errorMessage) {
  var header = CardService.newCardHeader()
    .setTitle("⚠️  Analysis Unavailable")
    .setSubtitle("Could not scan this email");

  var section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText("The email scanner is temporarily unavailable. Please try again in a moment.")
    )
    .addWidget(
      CardService.newTextParagraph()
        .setText("<font color='#888888'><i>" + errorMessage + "</i></font>")
    );

  return [
    CardService.newCardBuilder()
      .setHeader(header)
      .addSection(section)
      .build()
  ];
}
