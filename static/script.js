// ======================================
// PAGE NAVIGATION
// ======================================

function showPage(pageName) {

    const pages =
        document.querySelectorAll(".page");


    pages.forEach(function(page) {

        page.classList.add("hidden");

    });


    const selectedPage =
        document.getElementById(pageName);


    if (selectedPage) {

        selectedPage.classList.remove("hidden");

    }

}



// ======================================
// PCAP ANALYSIS
// ======================================

async function analyzePCAP() {

    const fileInput =
        document.getElementById("pcapFile");


    const status =
        document.getElementById("uploadStatus");


    if (fileInput.files.length === 0) {

        status.innerText =
            "Please select a PCAP file.";

        return;
    }


    const file =
        fileInput.files[0];


    status.innerText =
        "⏳ Analyzing PCAP...";


    const formData =
        new FormData();


    formData.append(
        "file",
        file
    );


    try {

        const response =
            await fetch(
                "/analyze",
                {
                    method: "POST",
                    body: formData
                }
            );


        const data =
            await response.json();


        if (!response.ok || data.error) {

            status.innerText =
                data.error ||
                "Analysis failed.";

            console.error(data);

            return;
        }


        // Display results

        displayResult(data);


        // Open result page

        showPage("results");


        status.innerText =
            "✅ Analysis completed successfully.";


    }
    catch (error) {

        console.error(error);


        status.innerText =
            "❌ Backend connection failed.";

    }

}



// ======================================
// DEMO
// ======================================

async function loadDemo(type) {

    try {

        const response =
            await fetch(
                "/demo/" + type
            );


        const data =
            await response.json();


        if (data.error) {

            alert(data.error);

            return;
        }


        displayResult(data);


        showPage("results");


    }
    catch (error) {

        console.error(error);

        alert(
            "Unable to load demo."
        );

    }

}



// ======================================
// DISPLAY RESULT
// ======================================

function displayResult(data) {

    const box =
        document.getElementById(
            "resultBox"
        );


    let riskClass = "";


    if (data.risk_level === "LOW") {

        riskClass = "risk-low";

    }
    else if (
        data.risk_level === "MEDIUM"
    ) {

        riskClass = "risk-medium";

    }
    else {

        riskClass = "risk-high";

    }


    box.innerHTML = `

        <div class="result-header">

            <h3>
                🔐 Security Assessment
            </h3>

            <span class="${riskClass}">
                ${data.risk_level}
            </span>

        </div>


        <div class="result-grid">


            <div class="result-card">

                <h4>Security Score</h4>

                <div class="big-number">

                    ${data.security_score}

                    <small>/100</small>

                </div>

            </div>


            <div class="result-card">

                <h4>AI Confidence</h4>

                <div class="big-number">

                    ${data.ai_confidence}%

                </div>

            </div>


            <div class="result-card">

                <h4>Total Packets</h4>

                <div class="big-number">

                    ${data.total_packets || "N/A"}

                </div>

            </div>

        </div>


        <p class="filename">

            <b>PCAP File:</b>
            ${data.filename}

        </p>


        <hr>


        <h3>
            ⚙️ IPsec Configuration
        </h3>


        <div class="configuration">


            <div>
                <b>IKE Version</b>
                <span>
                    ${data.ike_version}
                </span>
            </div>


            <div>
                <b>VPN Mode</b>
                <span>
                    ${data.vpn_mode}
                </span>
            </div>


            <div>
                <b>Encryption</b>
                <span>
                    ${data.encryption}
                </span>
            </div>


            <div>
                <b>Authentication</b>
                <span>
                    ${data.authentication}
                </span>
            </div>


            <div>
                <b>DH Group</b>
                <span>
                    ${data.dh_group}
                </span>
            </div>


            <div>
                <b>PFS</b>
                <span>
                    ${data.pfs}
                </span>
            </div>


            <div>
                <b>Replay Protection</b>
                <span>
                    ${data.replay_protection}
                </span>
            </div>


        </div>


        <hr>


        <h3>
            📡 Traffic Statistics
        </h3>


        <div class="traffic">


            <p>
                <b>IKE Packets:</b>
                ${data.ike_packets}
            </p>


            <p>
                <b>ESP Packets:</b>
                ${data.esp_packets}
            </p>


            <p>
                <b>AH Packets:</b>
                ${data.ah_packets}
            </p>


            <p>
                <b>UDP Packets:</b>
                ${data.udp_packets}
            </p>


            <p>
                <b>TCP Packets:</b>
                ${data.tcp_packets}
            </p>


        </div>

    `;
}



// ======================================
// REPORT
// ======================================

function generateReport() {

    const status =
        document.getElementById(
            "reportStatus"
        );


    status.innerText =
        "✅ Security report generated successfully!";

}