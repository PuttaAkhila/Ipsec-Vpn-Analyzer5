"""IPsec Insight working prototype: local PCAP analyzer + FastAPI dashboard.

Python >=3.10. Install: pip install fastapi 'uvicorn[standard]' python-multipart
Run: uvicorn ipsec_insight_working_model:app --host 127.0.0.1 --port 8000
Then open http://127.0.0.1:8000. PCAPNG conversion:
tshark -F pcap -r input.pcapng -w output.pcap

Research MVP only. No VPN decryption, live interface capture, or trained AI model.
Never expose this unauthenticated upload service publicly.
"""
from __future__ import annotations
import html, ipaddress, json, os, struct, tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="IPsec Insight", version="0.2.0", description="Evidence-first IPsec PCAP analysis MVP")
LAST_REPORT: Optional[dict] = None
MAX_PCAP = 100 * 1024 * 1024
MAX_JSON = 1024 * 1024
IKE_PORTS = {500, 4500}
EXCHANGES = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"}
ENDPOINT_KEYS = {
    "ike_version", "mode", "authentication", "ike_encryption", "ike_prf",
    "ike_dh_group", "esp_encryption", "esp_integrity", "esp_aead",
    "esp_key_bits", "esp_tag_bits", "child_dh_group", "pfs_enabled",
    "replay_protection", "replay_window", "ike_lifetime_seconds",
    "child_lifetime_seconds", "rekey_observed", "source", "timestamp_utc"
}

class CaptureError(ValueError):
    pass

def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()

def decode_transport(data: bytes, ts: float, src: str, dst: str, ipver: int, proto: int, length: int) -> dict:
    p = {"ts": ts, "src": src, "dst": dst, "ip_version": ipver, "protocol": proto,
         "length": length, "src_port": None, "dst_port": None, "payload": data}
    if proto == 17 and len(data) >= 8:
        p["src_port"] = int.from_bytes(data[:2], "big")
        p["dst_port"] = int.from_bytes(data[2:4], "big")
        p["payload"] = data[8:]
    elif proto == 6 and len(data) >= 20:
        p["src_port"] = int.from_bytes(data[:2], "big")
        p["dst_port"] = int.from_bytes(data[2:4], "big")
        offset = (data[12] >> 4) * 4
        p["payload"] = data[offset:] if offset <= len(data) else b""
    return p

def decode_ipv4(data: bytes, ts: float):
    if len(data) < 20 or data[0] >> 4 != 4: return None
    offset = (data[0] & 15) * 4
    if offset < 20 or len(data) < offset: return None
    length = min(int.from_bytes(data[2:4], "big") or len(data), len(data))
    if int.from_bytes(data[6:8], "big") & 0x1fff: return None  # non-initial fragment
    return decode_transport(data[offset:length], ts,
        str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20])),
        4, data[9], length)

def decode_ipv6(data: bytes, ts: float):
    if len(data) < 40 or data[0] >> 4 != 6: return None
    length = min(40 + int.from_bytes(data[4:6], "big"), len(data))
    next_header, offset = data[6], 40
    src, dst = str(ipaddress.ip_address(data[8:24])), str(ipaddress.ip_address(data[24:40]))
    for _ in range(12):
        if next_header in (0, 43, 60, 135, 139, 140):
            if offset + 2 > length: return None
            following, size = data[offset], (data[offset + 1] + 1) * 8
            next_header, offset = following, offset + size
        elif next_header == 44:
            if offset + 8 > length: return None
            if int.from_bytes(data[offset + 2:offset + 4], "big") & 0xfff8: return None
            next_header, offset = data[offset], offset + 8
        elif next_header == 51:
            if offset + 2 > length: return None
            following, size = data[offset], (data[offset + 1] + 2) * 4
            next_header, offset = following, offset + size
        else: break
    if offset > length: return None
    return decode_transport(data[offset:length], ts, src, dst, 6, next_header, length)

def decode_ethernet(data: bytes, ts: float):
    if len(data) < 14: return None
    kind, offset = int.from_bytes(data[12:14], "big"), 14
    while kind in (0x8100, 0x88a8, 0x9100):
        if len(data) < offset + 4: return None
        kind, offset = int.from_bytes(data[offset + 2:offset + 4], "big"), offset + 4
    if kind == 0x0800: return decode_ipv4(data[offset:], ts)
    if kind == 0x86dd: return decode_ipv6(data[offset:], ts)
    return None

def read_pcap(path: str):
    """Read classic PCAP with Ethernet or raw IPv4/IPv6 link type."""
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) != 24: raise CaptureError("Capture is too short for a PCAP header")
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
                   b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            raise CaptureError("PCAPNG needs conversion: tshark -F pcap -r input.pcapng -w output.pcap")
        if header[:4] not in formats: raise CaptureError("Unrecognized PCAP format")
        endian, scale = formats[header[:4]]
        _, major, minor, _, _, snaplen, link = struct.unpack(endian + "IHHIIII", header)
        if major != 2: raise CaptureError(f"Unsupported PCAP version {major}.{minor}")
        while True:
            record = f.read(16)
            if not record: break
            if len(record) != 16: raise CaptureError("Truncated PCAP record header")
            sec, frac, caplen, _ = struct.unpack(endian + "IIII", record)
            if caplen > min(max(snaplen, 65536), 64 * 1024 * 1024): raise CaptureError("Unreasonable packet length")
            raw = f.read(caplen)
            if len(raw) != caplen: raise CaptureError("Truncated packet data")
            ts = sec + frac * scale
            if link == 1: packet = decode_ethernet(raw, ts)
            elif link in (101, 228): packet = decode_ipv4(raw, ts) if raw and raw[0] >> 4 == 4 else None
            elif link == 229: packet = decode_ipv6(raw, ts)
            else: raise CaptureError("Supported PCAP link types: Ethernet (1), raw IPv4 (101/228), raw IPv6 (229)")
            if packet is not None: yield packet

def decode_ike(data: bytes):
    if len(data) < 28: return None
    declared, version = int.from_bytes(data[24:28], "big"), data[17]
    major = version >> 4
    if declared < 28 or declared > len(data) or major not in (1, 2): return None
    return {"version": f"IKEv{major}" + (f".{version & 15}" if major == 2 else ""),
            "exchange": EXCHANGES.get(data[18], f"EXCHANGE_{data[18]}"),
            "message_id": int.from_bytes(data[20:24], "big"),
            "initiator_spi": data[:8].hex(), "responder_spi": data[8:16].hex()}

def record_esp(sas, packet, payload, encapsulation):
    if len(payload) < 8: return
    spi, seq = int.from_bytes(payload[:4], "big"), int.from_bytes(payload[4:8], "big")
    key = (packet["src"], packet["dst"], spi)
    s = sas.setdefault(key, {"protocol": "ESP", "src": packet["src"], "dst": packet["dst"],
        "spi": f"{spi:08x}", "encapsulation": encapsulation, "packets": 0, "bytes": 0,
        "first": packet["ts"], "last": packet["ts"], "seq_min": seq, "seq_max": seq, "ip_versions": set()})
    s["packets"] += 1; s["bytes"] += packet["length"]
    s["first"] = min(s["first"], packet["ts"]); s["last"] = max(s["last"], packet["ts"])
    s["seq_min"] = min(s["seq_min"], seq); s["seq_max"] = max(s["seq_max"], seq)
    s["last_sequence"] = seq; s["ip_versions"].add(packet["ip_version"])

def make_finding(code, severity, title, evidence, recommendation, status="observed"):
    return {"id": code, "severity": severity, "status": status, "title": title,
            "evidence": evidence, "recommendation": recommendation}

def sanitize_endpoint(data):
    if not isinstance(data, dict): raise ValueError("Endpoint JSON must contain an object")
    return {k: v for k, v in data.items() if k in ENDPOINT_KEYS}

def analyze_capture(path: str, endpoint=None, capture_name=None):
    packets = list(read_pcap(path)); ike, sas = [], {}; counts = Counter(); flows = defaultdict(list)
    for p in packets:
        counts[f"IPv{p['ip_version']}"] += 1; payload = p["payload"]; is_ike = False
        if p["protocol"] == 17 and (p["src_port"] in IKE_PORTS or p["dst_port"] in IKE_PORTS):
            if p["src_port"] == 4500 or p["dst_port"] == 4500:
                if payload.startswith(b"\x00\x00\x00\x00"): payload, is_ike = payload[4:], True
                elif len(payload) >= 8: record_esp(sas, p, payload, "UDP/4500 NAT-T")
            else: is_ike = True
            if is_ike:
                msg = decode_ike(payload)
                if msg: ike.append({"timestamp": iso(p["ts"]), "src": p["src"], "dst": p["dst"], **msg})
        elif p["protocol"] == 50: record_esp(sas, p, payload, "native ESP")
        elif p["protocol"] == 51 and len(payload) >= 8:
            spi, seq = int.from_bytes(payload[:4], "big"), int.from_bytes(payload[4:8], "big")
            key = ("AH", p["src"], p["dst"], spi)
            s = sas.setdefault(key, {"protocol": "AH", "src": p["src"], "dst": p["dst"], "spi": f"{spi:08x}", "packets": 0, "bytes": 0})
            s["packets"] += 1; s["bytes"] += p["length"]; s["last_sequence"] = seq
        if p["protocol"] == 6 or (p["protocol"] == 17 and p["src_port"] not in IKE_PORTS and p["dst_port"] not in IKE_PORTS):
            flows[(p["src"], p["dst"])].append(p)
    for s in sas.values():
        if "first" in s:
            s["duration_seconds"] = round(s.pop("last") - s.pop("first"), 6)
            s["observed_sequence_span"] = [s.pop("seq_min"), s.pop("seq_max")]
            s["ip_versions"] = sorted(s["ip_versions"])
    ep = sanitize_endpoint(endpoint or {})
    versions = sorted({x["version"] for x in ike}); findings = []
    if "IKEv1" in versions:
        findings.append(make_finding("IKEV1-OBSERVED", "high", "IKEv1 traffic observed", "A decoded IKEv1 message is present.", "Migrate to an approved IKEv2 policy where feasible."))
    if not ep:
        findings.append(make_finding("ENDPOINT-EVIDENCE-MISSING", "info", "Endpoint evidence not supplied", "Passive packet evidence only.", "Provide authorized sanitized endpoint evidence to assess hidden SA properties.", "unknown"))
    enc = str(ep.get("esp_encryption", "")).lower().replace("-", "")
    if enc in {"des", "3des", "des3", "null"}:
        findings.append(make_finding("WEAK-ESP-ENCRYPTION", "high", "Weak/null ESP encryption reported", str(ep.get("esp_encryption")), "Replace with a suite approved by your organization."))
    if enc in {"aescbc", "cbc"} and not ep.get("esp_integrity"):
        findings.append(make_finding("CBC-INTEGRITY-UNVERIFIED", "high", "CBC integrity not evidenced", "AES-CBC reported without an integrity transform.", "Verify an approved integrity transform; this finding does not apply to AEAD."))
    if ep.get("pfs_enabled") is False:
        findings.append(make_finding("PFS-DISABLED", "medium", "Independent CHILD SA PFS reported disabled", "Endpoint telemetry reports pfs_enabled=false.", "Enable a fresh CHILD SA key exchange if required; verify with rekey evidence."))
    if ep.get("replay_protection") is False:
        findings.append(make_finding("REPLAY-PROTECTION-DISABLED", "high", "Replay protection reported disabled", "Endpoint telemetry reports replay_protection=false.", "Enable and verify receiver anti-replay enforcement."))
    if ep.get("rekey_observed") is False:
        findings.append(make_finding("REKEY-NOT-OBSERVED", "medium", "SA rekey not observed", "Endpoint evidence reports no rekey.", "Capture a renewal cycle; a short capture cannot prove rekey is disabled."))
    if ep.get("esp_key_bits") == 128:
        findings.append(make_finding("AES128-POLICY-REVIEW", "low", "AES-128 requires policy review", "128-bit AES reported; this is not automatically insecure.", "Compare with your organizational baseline.", "review"))
    # Risk is based only on explicitly supplied failing/review checks. Missing controls are not passes.
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
    assessed = [f for f in findings if f["severity"] in weights]
    denom = sum(weights[f["severity"]] for f in assessed)
    risk = round(100 * sum(weights[f["severity"]] for f in assessed if f["status"] in ("observed", "review")) / denom) if denom else (0 if ep else None)
    coverage = 100 if ep else 0  # coverage of the supplied prototype fields, not an enterprise audit
    traffic = []
    for (src, dst), group in flows.items():
        sizes = [p["length"] for p in group]; n = len(group); mean = sum(sizes) / n
        large = sum(x > 1000 for x in sizes) / n; small = sum(x < 180 for x in sizes) / n
        if n < 6: label, confidence = "unknown/insufficient samples", 0.0
        elif large > .30 and mean > 650: label, confidence = "bulk_or_video_like", .30
        elif small > .78 and mean < 180: label, confidence = "interactive_or_control", .35
        else: label, confidence = "unknown_or_mixed", .15
        traffic.append({"src": src, "dst": dst, "packet_count": n,
                        "prediction": {"label": label, "confidence": confidence, "method": "metadata heuristic"}})
    traffic.sort(key=lambda x: x["packet_count"], reverse=True); times = [p["ts"] for p in packets]
    return {"product": "IPsec Insight", "schema_version": "1.0",
        "capture": {"name": capture_name or os.path.basename(path), "packet_count": len(packets),
            "start_utc": iso(min(times)) if times else None, "end_utc": iso(max(times)) if times else None,
            "counts_by_ip_version": dict(counts)},
        "protocol": {"ike_versions": versions, "ike_message_count": len(ike), "ike_messages": ike[:5000], "sa_observations": list(sas.values())},
        "endpoint_evidence": ep, "traffic_inference": traffic[:1000],
        "assessment": {"risk_score": risk, "evidence_coverage": coverage,
            "score_note": "Prototype score over explicit supplied checks only; not certification. Missing evidence is not a pass.", "findings": findings},
        "limitations": ["Passive PCAP cannot reliably establish ESP transforms, tunnel/transport mode, configured lifetimes, replay enforcement, or CHILD SA PFS.",
            "Traffic labels are low-confidence metadata heuristics, not application identification.",
            "AES-GCM is AEAD; it does not require a separate HMAC.",
            "Sequence gaps do not prove a replay attack. Endpoint evidence is not independently verified."]}

def report_html(report):
    esc = html.escape
    rows = "".join(f"<tr><td>{esc(x['severity'])}</td><td>{esc(x['title'])}</td><td>{esc(x['evidence'])}</td><td>{esc(x['recommendation'])}</td></tr>" for x in report["assessment"]["findings"]) or "<tr><td colspan='4'>No findings</td></tr>"
    score = report["assessment"]["risk_score"]
    score = "Insufficient evidence" if score is None else f"{score}/100"
    limitations = "".join(f"<li>{esc(x)}</li>" for x in report["limitations"])
    traffic = esc(json.dumps(report["traffic_inference"], indent=2))
    return f"""<!doctype html><meta charset='utf-8'><title>IPsec Insight Report</title>
<style>body{{font:15px system-ui;max-width:1050px;margin:2rem auto;padding:1rem;color:#172033}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccd2dd;padding:.6rem;text-align:left;vertical-align:top}}th{{background:#eef2f8}}</style>
<h1>IPsec Insight â€” Assessment</h1><p>Capture: {esc(report['capture']['name'])}</p>
<p>Observed-risk score: <b>{score}</b> Â· Supplied endpoint evidence coverage: {report['assessment']['evidence_coverage']}% Â· Packets: {report['capture']['packet_count']}</p>
<h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr>{rows}</table>
<h2>Metadata traffic inference</h2><pre>{traffic}</pre><h2>Limitations</h2><ul>{limitations}</ul>"""

PAGE = """<!doctype html><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>IPsec Insight</title>
<style>body{font:16px system-ui;max-width:1000px;margin:2rem auto;padding:1rem;color:#172033;background:#f7f9fc}header,.card{background:white;border:1px solid #dce2ec;border-radius:14px;padding:1.2rem;margin:1rem 0}button{background:#0c7c91;color:white;border:0;padding:.7rem 1rem;border-radius:8px;cursor:pointer}pre{white-space:pre-wrap;overflow:auto;background:#f0f3f8;padding:1rem;border-radius:8px}.muted{color:#566174}</style>
<header><h1>IPsec Insight</h1><p>Evidence-first VPN capture analysis</p><p class='muted'>Report what is observed. Separate what is inferred. Mark what cannot be determined.</p></header>
<div class='card'><form id='upload'><p><label>Classic PCAP: <input name='capture' type='file' accept='.pcap,.cap' required></label></p><p><label>Sanitized endpoint JSON (optional): <input name='endpoint' type='file' accept='.json,application/json'></label></p><button>Analyze capture</button></form></div>
<div class='card'><button id='demo'>Load illustrative demo</button> <a href='/docs'>API docs</a> Â· <a href='/report'>HTML report</a></div>
<div class='card'><h2>Results</h2><pre id='output'>Upload a capture to begin. Demo data is synthetic.</pre></div>
<p class='muted'>Local research prototype. Classic PCAP only. No VPN decryption or live capture. Never upload keys or PSKs. Do not expose this unauthenticated service publicly.</p>
<script>const out=document.getElementById('output');document.getElementById('upload').onsubmit=async e=>{e.preventDefault();out.textContent='Analyzingâ€¦';let r=await fetch('/analyze',{method:'POST',body:new FormData(e.target)});let t=await r.text();try{out.textContent=JSON.stringify(JSON.parse(t),null,2)}catch{out.textContent=t}};document.getElementById('demo').onclick=async()=>{out.textContent='Generating synthetic sampleâ€¦';let r=await fetch('/demo',{method:'POST'});out.textContent=JSON.stringify(await r.json(),null,2)}</script>"""

@app.get("/", response_class=HTMLResponse)
def home(): return HTMLResponse(PAGE)

@app.post("/analyze")
async def upload_capture(capture: UploadFile = File(...), endpoint: Optional[UploadFile] = File(None)):
    global LAST_REPORT
    if not (capture.filename or "").lower().endswith((".pcap", ".cap")):
        raise HTTPException(415, "Upload classic PCAP; convert PCAPNG with tshark first.")
    path = None
    try:
        size = 0
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
            while True:
                chunk = await capture.read(1024 * 1024)
                if not chunk: break
                size += len(chunk)
                if size > MAX_PCAP: raise HTTPException(413, "PCAP limit is 100 MB")
                f.write(chunk)
        endpoint_data = {}
        if endpoint:
            raw = await endpoint.read(MAX_JSON + 1)
            if len(raw) > MAX_JSON: raise HTTPException(413, "Endpoint JSON limit is 1 MB")
            try: endpoint_data = json.loads(raw or b"{}")
            except json.JSONDecodeError as exc: raise HTTPException(400, "Invalid endpoint JSON") from exc
        LAST_REPORT = analyze_capture(path, endpoint_data, capture.filename)
        return JSONResponse(LAST_REPORT)
    except CaptureError as exc: raise HTTPException(400, str(exc)) from exc
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc
    finally:
        if path and os.path.exists(path): os.unlink(path)

@app.post("/demo")
def synthetic_demo():
    """Analyze fabricated synthetic IKEv2/ESP headers; no real network traffic."""
    global LAST_REPORT
    def ip4(src, dst, proto, body):
        n = 20 + len(body)
        return struct.pack("!BBHHHBBH4s4s", 0x45, 0, n, 1, 0, 64, proto, 0,
            bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.')))) + body
    def eth(body): return b"\x00" * 12 + b"\x08\x00" + body
    def udp(payload): return struct.pack("!HHHH", 500, 500, len(payload)+8, 0) + payload
    now = int(datetime.now(timezone.utc).timestamp())
    ike = bytes.fromhex("010203040506070800000000000000000000002200000000001c00000000")
    frames = [eth(ip4("192.0.2.10", "198.51.100.20", 17, udp(ike)))]
    for i in range(1, 13):
        esp = bytes.fromhex("11223344") + struct.pack("!I", i) + (b"\x00" * (80 if i % 3 else 1200))
        frames.append(eth(ip4("192.0.2.10", "198.51.100.20", 50, esp)))
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
        f.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            f.write(struct.pack("<IIII", now+i, 0, len(frame), len(frame)))
            f.write(frame)
    try:
        LAST_REPORT = analyze_capture(path, {}, "synthetic-demo.pcap")
        LAST_REPORT["demo_notice"] = "Illustrative synthetic packet headers; not a real capture or VPN assessment."
        return JSONResponse(LAST_REPORT)
    finally:
        os.unlink(path)

@app.get("/report", response_class=HTMLResponse)
def get_report():
    if LAST_REPORT is None: raise HTTPException(404, "Run an analysis first")
    return HTMLResponse(report_html(LAST_REPORT))

@app.get("/health")
def health(): return {"status": "ok", "service": "ipsec-insight"}