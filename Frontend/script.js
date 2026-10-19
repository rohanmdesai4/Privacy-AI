// PrivacyShield AI
// Educational frontend demonstration.
// Rule-based detection with context-aware risk assessment.

const inputText = document.getElementById("inputText");
const scanButton = document.getElementById("scanButton");
const clearButton = document.getElementById("clearButton");

const charCount = document.getElementById("charCount");
const emptyState = document.getElementById("emptyState");
const results = document.getElementById("results");

const riskLevel = document.getElementById("riskLevel");
const riskCount = document.getElementById("riskCount");
const riskList = document.getElementById("riskList");
const redactedOutput = document.getElementById("redactedOutput");
const actionSummary = document.getElementById("actionSummary");

const totalScans = document.getElementById("totalScans");
const totalRisks = document.getElementById("totalRisks");
const totalActions = document.getElementById("totalActions");

const activityBody = document.getElementById("activityBody");

let scanNumber = 0;
let riskTotal = 0;
let actionTotal = 0;


// --------------------------------------------------
// 1. SENSITIVE INFORMATION DETECTION RULES
// --------------------------------------------------

const detectionRules = [
    {
        name: "Credential Value",
        pattern: /\b(?:password|passwd|passcode|api[_ -]?key|access[_ -]?token|secret[_ -]?key)\b\s*(?::|=|\bis\b)\s*["']?([A-Za-z0-9_./+=-]{6,})["']?/gi,
        group: 1,
        severity: "HIGH",
        explanation:
            "A credential label appears to be followed by a possible secret value.",
        replacement: "[CREDENTIAL REDACTED]"
    },

    {
        name: "Email Address",
        pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
        group: 0,
        severity: "MEDIUM",
        explanation:
            "An email address may identify a person or organization.",
        replacement: "[EMAIL REDACTED]"
    },

    {
        name: "Phone Number",
        pattern: /(?<!\w)(?:\+91[\s.-]?)?[6-9]\d{9}(?!\w)/g,
        group: 0,
        severity: "MEDIUM",
        explanation:
            "A number matches a common Indian mobile-number format. Verify that it is not personal contact information.",
        replacement: "[PHONE NUMBER REDACTED]"
    },

    {
        name: "Confidential Business Information",
        pattern: /\b(?:confidential|proprietary|trade secret|internal use only|non-public)\b/gi,
        group: 0,
        severity: "HIGH",
        explanation:
            "The wording suggests that some information may be restricted or confidential.",
        replacement: "[CONFIDENTIAL REFERENCE REDACTED]"
    },

    {
        name: "Personal or Sensitive Records",
        pattern: /\b(?:personal information|customer records|employee records|medical records|bank account details|patient records)\b/gi,
        group: 0,
        severity: "HIGH",
        explanation:
            "The text refers to potentially sensitive personal, medical, or financial records.",
        replacement: "[SENSITIVE RECORD REFERENCE REDACTED]"
    },

    {
        name: "Financial Information",
        pattern: /\b(?:salary|payroll|bank details|financial statement|account balance|credit card number)\b/gi,
        group: 0,
        severity: "MEDIUM",
        explanation:
            "The wording may refer to private financial information.",
        replacement: "[FINANCIAL REFERENCE REDACTED]"
    },

    {
        name: "Potential Payment Card Number",
        pattern: /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,
        group: 0,
        severity: "HIGH",
        explanation:
            "A long digit sequence may be sensitive financial information. This rule does not verify whether it is a valid card number.",
        replacement: "[POSSIBLE CARD NUMBER REDACTED]"
    }
];


// --------------------------------------------------
// 2. CONTEXT ANALYSIS RULES
// --------------------------------------------------

const sharingPattern =
    /\b(?:share|send|forward|publish|post|upload|disclose|expose|email|message|submit)\b/i;

const externalRecipientPattern =
    /\b(?:public|publicly|everyone|anyone|social media|external users?|unknown recipients?|strangers|public website|internet)\b/i;

const privateRecipientPattern =
    /\b(?:private message|trusted colleague|authorized team|internal team|official support|my doctor|my lawyer)\b/i;


// Character counter.

inputText.addEventListener("input", function () {
    charCount.textContent = inputText.value.length + " characters";
});


// --------------------------------------------------
// 3. SCAN BUTTON
// --------------------------------------------------

scanButton.addEventListener("click", function () {
    const originalText = inputText.value;

    if (!originalText.trim()) {
        alert("Please enter some sample text before scanning.");
        inputText.focus();
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Analyzing...";

    setTimeout(function () {
        try {
            analyzeText(originalText);
        } catch (error) {
            console.error("Privacy scan failed:", error);
            alert("The scan could not be completed. Please try again.");
        } finally {
            scanButton.disabled = false;
            scanButton.textContent = "🔍 Analyze Privacy Risks";
        }
    }, 150);
});


// --------------------------------------------------
// 4. DETECT SENSITIVE INFORMATION
// --------------------------------------------------

function detectSensitiveInformation(text) {
    const detectedRisks = [];
    const matchesToRedact = [];

    detectionRules.forEach(function (rule) {
        rule.pattern.lastIndex = 0;

        const matches = [...text.matchAll(rule.pattern)];

        let validMatchCount = 0;

        matches.forEach(function (match) {
            const groupIndex = rule.group || 0;
            const sensitiveValue = match[groupIndex];

            if (!sensitiveValue) {
                return;
            }

            // Find the actual sensitive value rather than
            // replacing its descriptive label.
            const relativeStart =
                groupIndex === 0
                    ? 0
                    : match[0].lastIndexOf(sensitiveValue);

            const start = match.index + relativeStart;
            const end = start + sensitiveValue.length;

            matchesToRedact.push({
                start: start,
                end: end,
                replacement: rule.replacement,
                name: rule.name
            });

            validMatchCount++;
        });

        if (validMatchCount > 0) {
            detectedRisks.push({
                name: rule.name,
                severity: rule.severity,
                explanation: rule.explanation,
                count: validMatchCount
            });
        }
    });

    return {
        detectedRisks: detectedRisks,
        matchesToRedact: matchesToRedact
    };
}


// --------------------------------------------------
// 5. ANALYZE CONTEXT AND RECOMMEND ACTIONS
// --------------------------------------------------

function analyzeContext(text, detectedRisks) {
    const sharesInformation = sharingPattern.test(text);
    const mentionsExternalRecipient =
        externalRecipientPattern.test(text);
    const mentionsPrivateRecipient =
        privateRecipientPattern.test(text);

    const hasHighRisk = detectedRisks.some(function (risk) {
        return risk.severity === "HIGH";
    });

    const hasSensitiveInformation = detectedRisks.length > 0;

    let contextRisk = "LOW";
    let explanation =
        "No clear high-risk sharing pattern was detected by the current rules.";

    if (
        hasSensitiveInformation &&
        sharesInformation &&
        mentionsExternalRecipient
    ) {
        contextRisk = "HIGH";

        explanation =
            "The text contains potential sensitive information and mentions sharing or sending information to a public or external audience. Verify authorization before sharing.";
    } else if (
        hasSensitiveInformation &&
        sharesInformation
    ) {
        contextRisk = hasHighRisk ? "HIGH" : "MEDIUM";

        explanation =
            "The text contains potential sensitive information and a sharing-related action. Check the recipient and remove unnecessary sensitive details before sharing.";
    } else if (hasHighRisk) {
        contextRisk = "HIGH";

        explanation =
            "Potentially sensitive credentials or restricted information were detected. Avoid sharing actual secrets or confidential details.";
    } else if (hasSensitiveInformation) {
        contextRisk = "MEDIUM";

        explanation =
            "Potentially sensitive information was detected. Review whether it needs to appear in the message.";
    }

    if (
        mentionsPrivateRecipient &&
        contextRisk === "HIGH" &&
        !mentionsExternalRecipient
    ) {
        explanation +=
            " A private or authorized recipient is also mentioned, but the wording alone cannot verify that the recipient is authorized.";
    }

    return {
        risk: contextRisk,
        explanation: explanation,
        sharesInformation: sharesInformation,
        mentionsExternalRecipient: mentionsExternalRecipient
    };
}


// --------------------------------------------------
// 6. REMOVE OVERLAPPING REDACTION RANGES
// --------------------------------------------------

function removeOverlappingMatches(matches) {
    const sortedMatches = [...matches].sort(function (a, b) {
        return a.start - b.start || b.end - a.end;
    });

    const filteredMatches = [];

    sortedMatches.forEach(function (match) {
        const previous = filteredMatches[filteredMatches.length - 1];

        if (!previous || match.start >= previous.end) {
            filteredMatches.push(match);
        }
    });

    return filteredMatches;
}


// --------------------------------------------------
// 7. CREATE PROTECTED TEXT
// --------------------------------------------------

function redactText(originalText, matches) {
    let protectedText = originalText;

    for (let i = matches.length - 1; i >= 0; i--) {
        const match = matches[i];

        protectedText =
            protectedText.slice(0, match.start) +
            match.replacement +
            protectedText.slice(match.end);
    }

    return protectedText;
}


// --------------------------------------------------
// 8. DISPLAY A RISK CARD SAFELY
// --------------------------------------------------

function createRiskCard(name, severity, explanation, count) {
    const item = document.createElement("div");
    item.className = "risk-item";

    const title = document.createElement("strong");
    title.textContent = count
        ? name + " (" + count + ")"
        : name;

    const description = document.createElement("p");
    description.textContent = explanation;

    const tag = document.createElement("span");
    tag.className = "risk-tag tag-" + severity.toLowerCase();
    tag.textContent = severity + " RISK";

    item.append(title, description, tag);

    return item;
}


// --------------------------------------------------
// 9. MAIN ANALYSIS FUNCTION
// --------------------------------------------------

function analyzeText(originalText) {
    const detection = detectSensitiveInformation(originalText);

    const detectedRisks = detection.detectedRisks;
    const matchesToRedact = detection.matchesToRedact;

    const filteredMatches =
        removeOverlappingMatches(matchesToRedact);

    const context = analyzeContext(originalText, detectedRisks);

    const overallRisk = context.risk;

    const protectedText =
        redactText(originalText, filteredMatches);

    // Show the results panel.

    emptyState.hidden = true;
    results.hidden = false;

    riskLevel.textContent = overallRisk;
    riskLevel.className = "risk-" + overallRisk.toLowerCase();

    // Include the context assessment in the displayed count.

    riskCount.textContent = detectedRisks.length + 1;

    riskList.replaceChildren();

    // Always explain the context assessment.

    riskList.appendChild(
        createRiskCard(
            "Contextual Sharing Analysis",
            context.risk,
            context.explanation
        )
    );

    if (detectedRisks.length === 0) {
        const message = document.createElement("div");
        message.className = "risk-item";

        const title = document.createElement("strong");
        title.textContent = "No matching sensitive-data rules triggered";

        const description = document.createElement("p");
        description.textContent =
            "This does not guarantee that the message is safe. " +
            "The detector may miss sensitive information that its rules do not recognize.";

        message.append(title, description);
        riskList.appendChild(message);
    }

    detectedRisks.forEach(function (risk) {
        riskList.appendChild(
            createRiskCard(
                risk.name,
                risk.severity,
                risk.explanation,
                risk.count
            )
        );
    });

    // Display the protected preview as plain text.

    redactedOutput.textContent = protectedText;

    // Give a practical recommendation.

    let recommendation;

    if (overallRisk === "HIGH") {
        recommendation =
            "⚠️ HIGH RISK: Do not share this message yet. Review the detected items, remove actual secrets, and confirm that the recipient is authorized.";
    } else if (overallRisk === "MEDIUM") {
        recommendation =
            "🔎 MEDIUM RISK: Review the detected information and remove personal details that are not necessary before sharing.";
    } else {
        recommendation =
            "✅ LOW RISK: No high-risk pattern was identified. Review the message manually before sharing because this scan cannot guarantee privacy.";
    }

    if (filteredMatches.length > 0) {
        actionSummary.textContent =
            recommendation +
            " " +
            filteredMatches.length +
            " text segment(s) were redacted in the preview only.";
    } else {
        actionSummary.textContent = recommendation;
    }

    // Update dashboard statistics.

    scanNumber++;
    riskTotal += detectedRisks.length;
    actionTotal += filteredMatches.length;

    totalScans.textContent = scanNumber;
    totalRisks.textContent = riskTotal;
    totalActions.textContent = actionTotal;

    // Add a new activity record.

    const emptyRow = document.getElementById("noActivity");

    if (emptyRow) {
        emptyRow.remove();
    }

    const row = document.createElement("tr");

    const scanCell = document.createElement("td");
    scanCell.textContent = "#" + scanNumber;

    const levelCell = document.createElement("td");
    levelCell.textContent = overallRisk;

    const countCell = document.createElement("td");
    countCell.textContent = detectedRisks.length;

    const actionCell = document.createElement("td");
    actionCell.textContent =
        filteredMatches.length > 0
            ? "Redacted in preview"
            : "No matching rules";

    row.append(scanCell, levelCell, countCell, actionCell);

    activityBody.prepend(row);
}


// --------------------------------------------------
// 10. CLEAR BUTTON
// --------------------------------------------------

clearButton.addEventListener("click", function () {
    inputText.value = "";

    charCount.textContent = "0 characters";

    emptyState.hidden = false;
    results.hidden = true;

    inputText.focus();
});