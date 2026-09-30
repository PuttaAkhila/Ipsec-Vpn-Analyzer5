from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import os

from analyzer import analyze_pcap


app = FastAPI(
    title="AI Powered IPsec VPN Analyzer",
    version="1.0"
)


# =============================
# STATIC FILES
# =============================

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


# =============================
# HOME
# =============================

@app.get("/")
async def home():
    return FileResponse(
        "templates/index.html"
    )


# =============================
# HEALTH CHECK
# =============================

@app.get("/health")
async def health():

    return {
        "status": "running",
        "message": "IPsec VPN Analyzer Backend is Working!"
    }


# =============================
# PCAP ANALYSIS
# =============================

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):

    if not file.filename:

        return {
            "error": "Please select a PCAP file."
        }


    # Check PCAP extension

    if not file.filename.lower().endswith(
        (".pcap", ".pcapng")
    ):

        return {
            "error": "Only .pcap and .pcapng files are supported."
        }


    # Create upload directory

    os.makedirs(
        "uploads",
        exist_ok=True
    )


    # Save file

    file_path = os.path.join(
        "uploads",
        file.filename
    )


    content = await file.read()


    with open(
        file_path,
        "wb"
    ) as f:

        f.write(content)


    # Analyze

    try:

        result = analyze_pcap(
            file_path
        )

    except Exception as e:

        return {
            "error": "PCAP analysis failed.",
            "details": str(e)
        }


    result["filename"] = file.filename

    return result


# =============================
# DEMO DATA
# =============================

@app.get("/demo/{scenario}")
async def demo(scenario: str):

    scenarios = {

        "strong": {

            "filename": "Strong-IPsec-Demo.pcap",

            "security_score": 91,

            "risk_level": "LOW",

            "ai_confidence": 94,

            "ike_version": "IKEv2",

            "vpn_mode": "Tunnel",

            "encryption": "AES-256-GCM",

            "authentication": "HMAC-SHA256",

            "dh_group": "Group 19",

            "pfs": "Enabled",

            "replay_protection": "Enabled"
        },


        "moderate": {

            "filename": "Moderate-IPsec-Demo.pcap",

            "security_score": 72,

            "risk_level": "MEDIUM",

            "ai_confidence": 86,

            "ike_version": "IKEv2",

            "vpn_mode": "Tunnel",

            "encryption": "AES-128",

            "authentication": "HMAC-SHA256",

            "dh_group": "Group 14",

            "pfs": "Enabled",

            "replay_protection": "Enabled"
        },


        "weak": {

            "filename": "Weak-IPsec-Demo.pcap",

            "security_score": 42,

            "risk_level": "HIGH",

            "ai_confidence": 78,

            "ike_version": "IKEv1",

            "vpn_mode": "Transport",

            "encryption": "3DES",

            "authentication": "MD5",

            "dh_group": "Group 2",

            "pfs": "Disabled",

            "replay_protection": "Disabled"
        }
    }


    if scenario not in scenarios:

        return {
            "error": "Scenario not found."
        }


    return scenarios[scenario]