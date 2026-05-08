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
// Structure we decided on:
//   1. Risk level + Score + Confidence
//   2. Reasoning (AI explanation)
//   3. WHY — risk factors (up to 4)
//   4. WHAT TO DO
// ---------------------------------------------------------------------------
function buildResultCard(result) {
  var verdict         = result.verdict;
  var score           = result.final_score;
  var confidence      = result.confidence;
  var confidenceDots  = result.confidence_dots;
  var riskFactors     = result.risk_factors  || [];
  var reasoning       = result.reasoning     || "";
  var whatToDo        = result.what_to_do    || "";

  // ── Header: icon + verdict + score ──────────────────────────────────────
  var icon = verdict === "Safe" ? "✅" : verdict === "Suspicious" ? "⚠️" : "🚨";

  var header = CardService.newCardHeader()
    .setTitle(icon + "  " + verdict)
    .setSubtitle("Score: " + score + " / 100   " + confidenceDots + " " + confidence);

  // ── Section 1: AI summary (one short sentence) ──────────────────────────
  var summarySection = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText("<i>" + reasoning + "</i>")
    );

  // ── Section 2: WHY (bullet points) ──────────────────────────────────────
  var whySection = CardService.newCardSection()
    .setHeader("⚠️ WHY");

  if (riskFactors.length === 0) {
    whySection.addWidget(
      CardService.newTextParagraph().setText("✔  No specific risks detected.")
    );
  } else {
    riskFactors.forEach(function(factor) {
      whySection.addWidget(
        CardService.newDecoratedText()
          .setText(factor)
          .setStartIcon(CardService.newIconImage()
            .setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/warning_red_18dp.png"))
          .setWrapText(true)
      );
    });
  }

  // ── Section 3: WHAT TO DO ────────────────────────────────────────────────
  var whatToDoSection = CardService.newCardSection()
    .setHeader("✅ WHAT TO DO")
    .addWidget(
      CardService.newTextParagraph().setText("<b>" + whatToDo + "</b>")
    );

  // ── Assemble card ────────────────────────────────────────────────────────
  return [
    CardService.newCardBuilder()
      .setHeader(header)
      .addSection(summarySection)
      .addSection(whySection)
      .addSection(whatToDoSection)
      .build()
  ];
}


// ---------------------------------------------------------------------------
// BUILD ERROR CARD
// Shown when the backend is unreachable or returns an error.
// ---------------------------------------------------------------------------
function buildErrorCard(errorMessage) {
  var header = CardService.newCardHeader()
    .setTitle("⚠️  Analysis Failed");

  var section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText("Could not analyze this email.\n\n" + errorMessage)
    );

  return [
    CardService.newCardBuilder()
      .setHeader(header)
      .addSection(section)
      .build()
  ];
}
