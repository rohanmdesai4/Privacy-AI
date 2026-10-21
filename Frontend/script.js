document.addEventListener("DOMContentLoaded", () => {

    const API_URL = "https://privacy-ai.onrender.com";

    // ----------------------------------------------------
    // FIND TEXTAREA
    // ----------------------------------------------------

    const textarea = document.querySelector("textarea");

    if (!textarea) {
        console.error("ERROR: Textarea not found.");
        return;
    }


    // ----------------------------------------------------
    // FIND ANALYZE BUTTON
    // ----------------------------------------------------

    const buttons = Array.from(
        document.querySelectorAll("button")
    );

    const analyzeButton = buttons.find(button =>
        button.textContent
            .trim()
            .toLowerCase()
            .includes("analyze privacy")
    );

    if (!analyzeButton) {
        console.error(
            "ERROR: Analyze Privacy button not found."
        );
        return;
    }


    // ----------------------------------------------------
    // FIND RESULT AREA
    // ----------------------------------------------------

    function findResultArea() {

        const allElements = Array.from(
            document.querySelectorAll("*")
        );


        // Find "Ready to Analyze"

        const readyElement = allElements.find(element => {

            return (
                element.children.length === 0 &&
                element.textContent
                    .trim()
                    .toLowerCase() ===
                "ready to analyze"
            );

        });


        if (readyElement) {

            let parent =
                readyElement.parentElement;

            for (
                let i = 0;
                i < 5 && parent;
                i++
            ) {

                if (
                    parent.querySelector("h2") ||
                    parent.querySelector("h3")
                ) {
                    return parent;
                }

                parent =
                    parent.parentElement;
            }

            return readyElement.parentElement;
        }


        // Backup: find Privacy Analysis heading

        const privacyHeading =
            allElements.find(element => {

                return (
                    element.children.length === 0 &&
                    element.textContent
                        .trim()
                        .toLowerCase() ===
                    "privacy analysis"
                );

            });


        if (privacyHeading) {
            return privacyHeading.parentElement;
        }


        return null;
    }


    // ----------------------------------------------------
    // ESCAPE HTML
    // ----------------------------------------------------

    function escapeHTML(value) {

        if (
            value === null ||
            value === undefined
        ) {
            return "";
        }


        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }


    // ----------------------------------------------------
    // FORMAT RISK OBJECT
    // ----------------------------------------------------

    function formatRisk(risk) {

        // If backend sends normal text
        if (
            typeof risk === "string" ||
            typeof risk === "number"
        ) {

            return escapeHTML(risk);
        }


        // If backend sends an object
        if (
            typeof risk === "object" &&
            risk !== null
        ) {

            // Try common field names first

            const title =
                risk.type ||
                risk.category ||
                risk.entity ||
                risk.name ||
                risk.label ||
                "Privacy Risk";


            const description =
                risk.message ||
                risk.description ||
                risk.reason ||
                risk.details ||
                "";


            const value =
                risk.value ||
                risk.text ||
                risk.detected_text ||
                risk.content ||
                "";


            let html = `
                <div style="
                    padding: 12px;
                    margin: 8px 0;
                    border-radius: 8px;
                    background: rgba(255,255,255,0.08);
                ">
                    <strong>
                        ⚠️ ${escapeHTML(title)}
                    </strong>
            `;


            if (description) {

                html += `
                    <div style="
                        margin-top: 5px;
                    ">
                        ${escapeHTML(description)}
                    </div>
                `;
            }


            if (value) {

                html += `
                    <div style="
                        margin-top: 5px;
                        font-size: 13px;
                        opacity: 0.85;
                    ">
                        Detected:
                        ${escapeHTML(value)}
                    </div>
                `;
            }


            // If none of the expected fields exist,
            // display the actual object instead of
            // [object Object].

            if (
                !description &&
                !value &&
                !risk.type &&
                !risk.category &&
                !risk.entity &&
                !risk.name &&
                !risk.label
            ) {

                html += `
                    <div style="
                        margin-top: 5px;
                        font-size: 13px;
                    ">
                        ${escapeHTML(
                            JSON.stringify(risk)
                        )}
                    </div>
                `;
            }


            html += `</div>`;


            return html;
        }


        return escapeHTML(String(risk));
    }


    // ----------------------------------------------------
    // DISPLAY RESULT
    // ----------------------------------------------------

    function showResult(data) {

        console.log(
            "API RESULT:",
            data
        );


        const resultArea =
            findResultArea();


        if (!resultArea) {

            console.error(
                "Could not find Privacy Analysis result area."
            );


            alert(
                "Backend worked, but the Privacy Analysis area could not be found."
            );


            return;
        }


        // ------------------------------------------------
        // GET BACKEND DATA
        // ------------------------------------------------

        const privacyLevel =
            data.privacy_level ??
            "Unknown";


        const protectedText =
            data.processed_text ??
            data.protected_text ??
            "";


        const originalText =
            data.original_text ??
            "";


        const risks =
            Array.isArray(data.risks)
                ? data.risks
                : [];


        const itemsFound =
            Array.isArray(data.items_found)
                ? data.items_found
                : [];


        // ------------------------------------------------
        // PRIVACY RISKS
        // ------------------------------------------------

        let risksHTML = "";


        if (risks.length === 0) {

            risksHTML = `
                <div
                    class="privacy-result-box"
                    style="
                        margin-top: 15px;
                        padding: 15px;
                        border-radius: 10px;
                        background: rgba(255,255,255,0.08);
                    "
                >

                    <h3>
                        🛡️ Privacy Risks
                    </h3>

                    <p>
                        ✅ No privacy risks detected.
                    </p>

                </div>
            `;

        } else {

            risksHTML = `
                <div
                    class="privacy-result-box"
                    style="
                        margin-top: 15px;
                        padding: 15px;
                        border-radius: 10px;
                        background: rgba(255,255,255,0.08);
                    "
                >

                    <h3>
                        ⚠️ Privacy Risks
                    </h3>

                    <div>

                        ${risks
                            .map(risk =>
                                formatRisk(risk)
                            )
                            .join("")
                        }

                    </div>

                </div>
            `;
        }


        // ------------------------------------------------
        // SENSITIVE INFORMATION
        // ------------------------------------------------

        let itemsHTML = "";


        if (itemsFound.length > 0) {

            itemsHTML = `
                <div
                    class="privacy-result-box"
                    style="
                        margin-top: 15px;
                        padding: 15px;
                        border-radius: 10px;
                        background: rgba(255,255,255,0.08);
                    "
                >

                    <h3>
                        🔎 Sensitive Information Found
                    </h3>

                    <ul>

                        ${itemsFound
                            .map(item => {

                                if (
                                    typeof item === "object" &&
                                    item !== null
                                ) {

                                    return `
                                        <li>
                                            ${escapeHTML(
                                                JSON.stringify(item)
                                            )}
                                        </li>
                                    `;
                                }


                                return `
                                    <li>
                                        ${escapeHTML(item)}
                                    </li>
                                `;

                            })
                            .join("")
                        }

                    </ul>

                </div>
            `;
        }


        // ------------------------------------------------
        // PRIVACY LEVEL
        // ------------------------------------------------

        const level =
            String(privacyLevel)
                .toLowerCase();


        let levelIcon = "🔐";


        if (level.includes("critical")) {
            levelIcon = "🚨";
        }
        else if (level.includes("high")) {
            levelIcon = "🔴";
        }
        else if (level.includes("medium")) {
            levelIcon = "🟠";
        }
        else if (level.includes("low")) {
            levelIcon = "🟢";
        }


        // ------------------------------------------------
        // FINAL RESULT
        // ------------------------------------------------

        resultArea.innerHTML = `

            <div
                style="
                    width: 100%;
                    box-sizing: border-box;
                    padding: 20px;
                "
            >

                <h2>
                    🔐 Privacy Analysis
                </h2>


                <!-- PRIVACY LEVEL -->

                <div
                    style="
                        margin-top: 15px;
                        padding: 18px;
                        border-radius: 12px;
                        background: rgba(255,255,255,0.12);
                        text-align: center;
                    "
                >

                    <h3>
                        Privacy Level
                    </h3>


                    <div
                        style="
                            font-size: 24px;
                            font-weight: bold;
                            margin-top: 8px;
                        "
                    >

                        ${levelIcon}
                        ${escapeHTML(
                            String(
                                privacyLevel
                            ).toUpperCase()
                        )}

                    </div>

                </div>


                <!-- RISKS -->

                ${risksHTML}


                <!-- SENSITIVE ITEMS -->

                ${itemsHTML}


                <!-- PROTECTED TEXT -->

                <div
                    class="privacy-result-box"
                    style="
                        margin-top: 15px;
                        padding: 15px;
                        border-radius: 10px;
                        background: rgba(255,255,255,0.08);
                    "
                >

                    <h3>
                        🛡️ Protected Text
                    </h3>


                    <div
                        style="
                            margin-top: 10px;
                            padding: 15px;
                            border-radius: 10px;
                            background: rgba(0,0,0,0.25);
                            white-space: pre-wrap;
                            word-break: break-word;
                        "
                    >

                        ${escapeHTML(
                            protectedText
                        )}

                    </div>

                </div>


                <!-- ORIGINAL TEXT -->

                <div
                    class="privacy-result-box"
                    style="
                        margin-top: 15px;
                        padding: 15px;
                        border-radius: 10px;
                        background: rgba(255,255,255,0.05);
                    "
                >

                    <h3>
                        📄 Original Text
                    </h3>


                    <div
                        style="
                            margin-top: 10px;
                            padding: 15px;
                            border-radius: 10px;
                            background: rgba(0,0,0,0.15);
                            white-space: pre-wrap;
                            word-break: break-word;
                            opacity: 0.85;
                        "
                    >

                        ${escapeHTML(
                            originalText
                        )}

                    </div>

                </div>


            </div>
        `;


        console.log(
            "RESULT DISPLAYED SUCCESSFULLY"
        );
    }


    // ----------------------------------------------------
    // ANALYZE BUTTON
    // ----------------------------------------------------

    analyzeButton.addEventListener(
        "click",
        async (event) => {

            event.preventDefault();


            const text =
                textarea.value.trim();


            if (!text) {

                alert(
                    "Please enter some text first."
                );

                return;
            }


            const oldButtonText =
                analyzeButton.innerHTML;


            analyzeButton.disabled = true;

            analyzeButton.innerHTML =
                "⏳ Analyzing...";


            try {

                console.log(
                    "Sending request to:",
                    `${API_URL}/privacy`
                );


                // ------------------------------------------------
                // CALL FASTAPI
                // ------------------------------------------------

                const response =
                    await fetch(
                        `${API_URL}/privacy`,
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json",

                                "Accept":
                                    "application/json"
                            },

                            body: JSON.stringify({
                                text: text
                            })
                        }
                    );


                console.log(
                    "HTTP Status:",
                    response.status
                );


                // Get raw response

                const responseText =
                    await response.text();


                console.log(
                    "Backend Response:",
                    responseText
                );


                if (!response.ok) {

                    throw new Error(
                        `HTTP ${response.status}: ${responseText}`
                    );
                }


                // ------------------------------------------------
                // PARSE JSON
                // ------------------------------------------------

                let data;


                try {

                    data =
                        JSON.parse(
                            responseText
                        );

                }
                catch (error) {

                    throw new Error(
                        "Backend did not return valid JSON."
                    );
                }


                // ------------------------------------------------
                // DISPLAY
                // ------------------------------------------------

                showResult(data);


            }
            catch (error) {

                console.error(
                    "PRIVACY API ERROR:",
                    error
                );


                alert(
                    "Error while analyzing text.\n\n" +
                    error.message
                );

            }
            finally {

                analyzeButton.disabled =
                    false;

                analyzeButton.innerHTML =
                    oldButtonText;
            }

        }
    );


    console.log(
        "PrivacyShield script.js loaded successfully."
    );

});