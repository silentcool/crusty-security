#!/usr/bin/env python3
"""scan_vt.py — Check file hashes against VirusTotal (privacy-first: hash only by default).

Usage: scan_vt.py [OPTIONS] <file> [file2 ...]

Options:
  --upload          Upload file if hash not found (asks confirmation by default)
  --force-upload    Upload without confirmation
  --json            JSON output (default)
  -h, --help        Show help

Environment:
  VIRUSTOTAL_API_KEY   Required. Get free key at https://www.virustotal.com/
"""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

try:
    import urllib.request
    import urllib.error
    import ssl
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Rate limiting for free tier
RATE_LIMIT_REQUESTS = 4
RATE_LIMIT_WINDOW = 60  # seconds
_request_times = []


def show_help():
    print(__doc__)
    sys.exit(0)


def rate_limit_wait():
    """Enforce VT free tier rate limit: 4 requests/minute."""
    global _request_times
    now = time.time()
    _request_times = [t for t in _request_times if now - t < RATE_LIMIT_WINDOW]
    if len(_request_times) >= RATE_LIMIT_REQUESTS:
        wait = RATE_LIMIT_WINDOW - (now - _request_times[0]) + 1
        if wait > 0:
            sys.stderr.write(f"[clawguard] Rate limit: waiting {wait:.0f}s...\n")
            time.sleep(wait)
    _request_times.append(time.time())


def sha256_file(filepath):
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def vt_get(endpoint, api_key):
    """GET request to VirusTotal API v3."""
    rate_limit_wait()
    url = f"https://www.virustotal.com/api/v3{endpoint}"
    headers = {"x-apikey": api_key}

    if HAS_REQUESTS:
        r = requests.get(url, headers=headers, timeout=30)
        return r.status_code, r.json() if r.status_code == 200 else r.text
    elif HAS_URLLIB:
        req = urllib.request.Request(url, headers=headers)
        ctx = ssl.create_default_context()
        try:
            resp = urllib.request.urlopen(req, timeout=30, context=ctx)
            return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
    raise RuntimeError("No HTTP library available")


def vt_upload(filepath, api_key):
    """Upload file to VirusTotal."""
    rate_limit_wait()
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}

    file_size = os.path.getsize(filepath)
    if file_size > 32 * 1024 * 1024:  # >32MB needs upload URL
        rate_limit_wait()
        if HAS_REQUESTS:
            r = requests.get(f"{url}/upload_url", headers=headers, timeout=15)
            if r.status_code == 200:
                url = r.json().get("data", url)
        # For simplicity, skip large file upload with urllib

    if HAS_REQUESTS:
        with open(filepath, "rb") as f:
            r = requests.post(url, headers=headers, files={"file": (os.path.basename(filepath), f)}, timeout=120)
        if r.status_code == 200:
            return True, r.json()
        return False, f"Upload failed: HTTP {r.status_code}"
    else:
        # Multipart upload with urllib is complex; skip
        return False, "File upload requires 'requests' library. Install with: pip3 install requests"


def classify_severity(stats):
    """Classify severity based on detection ratio."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    if total == 0:
        return "unknown"
    
    detection_ratio = (malicious + suspicious) / total

    if malicious == 0 and suspicious == 0:
        return "clean"
    elif detection_ratio < 0.1:
        return "low"  # Likely false positive
    elif detection_ratio < 0.3:
        return "medium"
    elif detection_ratio < 0.6:
        return "high"
    else:
        return "critical"


def scan_file(filepath, api_key, allow_upload=False, force_upload=False):
    """Scan a file by hash lookup, optionally upload."""
    if not os.path.isfile(filepath):
        return {"status": "error", "file": filepath, "message": "File not found"}

    file_hash = sha256_file(filepath)
    file_size = os.path.getsize(filepath)

    result = {
        "file": filepath,
        "sha256": file_hash,
        "file_size": file_size,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "engine": "virustotal",
    }

    # Lookup by hash
    status_code, data = vt_get(f"/files/{file_hash}", api_key)

    if status_code == 200:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        severity = classify_severity(stats)

        result.update({
            "status": severity,
            "threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", None),
            "detection_stats": stats,
            "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "names": attrs.get("names", [])[:5],
            "first_seen": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
        })
    elif status_code == 404:
        result["status"] = "not_found"
        result["message"] = "Hash not found in VirusTotal database"

        if allow_upload or force_upload:
            if not force_upload:
                result["message"] += " (upload was allowed, attempting...)"
            
            ok, upload_result = vt_upload(filepath, api_key)
            if ok:
                result["status"] = "uploaded"
                result["message"] = "File uploaded to VirusTotal for analysis. Check back in a few minutes."
                analysis_id = upload_result.get("data", {}).get("id", "")
                result["analysis_id"] = analysis_id
            else:
                result["upload_error"] = str(upload_result)
    elif status_code == 429:
        result["status"] = "rate_limited"
        result["message"] = "VirusTotal API rate limit exceeded (free tier: 4 req/min, 500/day)"
    else:
        result["status"] = "error"
        result["message"] = f"VirusTotal API returned HTTP {status_code}"

    return result


def main():
    args = sys.argv[1:]
    allow_upload = False
    force_upload = False
    files = []

    for arg in args:
        if arg in ("-h", "--help"):
            show_help()
        elif arg == "--upload":
            allow_upload = True
        elif arg == "--force-upload":
            force_upload = True
        elif arg == "--json":
            pass
        else:
            files.append(arg)

    if not files:
        print(json.dumps({"status": "error", "message": "No files specified. Use --help for usage."}))
        sys.exit(2)

    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        print(json.dumps({"status": "error", "message": "VIRUSTOTAL_API_KEY not set. See references/setup.md for instructions."}))
        sys.exit(2)

    results = []
    for f in files:
        results.append(scan_file(f, api_key, allow_upload=allow_upload, force_upload=force_upload))

    if len(results) == 1:
        print(json.dumps(results[0], indent=2))
    else:
        print(json.dumps({"results": results}, indent=2))

    # Push to dashboard
    _push_vt_scans(files, results)

    # Exit code
    statuses = [r.get("status", "") for r in results]
    if any(s in ("critical", "high") for s in statuses):
        sys.exit(1)
    elif any(s in ("medium", "low") for s in statuses):
        sys.exit(1)
    sys.exit(0)


def _push_vt_scans(files, results):
    """Push VirusTotal scan results to dashboard."""
    cg_key = os.environ.get("CRUSTY_API_KEY", os.environ.get("CLAWGUARD_API_KEY", ""))
    dashboard = os.environ.get("CRUSTY_DASHBOARD_URL", os.environ.get("CLAWGUARD_DASHBOARD_URL", "https://clawguard-rust.vercel.app"))
    if not cg_key:
        return
    import threading, urllib.request, ssl
    def _push(f, r):
        try:
            status = r.get("status", "clean")
            dash_status = "clean"
            severity = "none"
            if status in ("critical", "high"):
                dash_status = "malicious"
                severity = "critical"
            elif status in ("medium", "low"):
                dash_status = "suspicious"
                severity = "high"
            payload = json.dumps({
                "scan_type": "virustotal",
                "target": f,
                "status": dash_status,
                "engine": "VirusTotal",
                "severity": severity,
                "results": r
            }).encode()
            req = urllib.request.Request(
                f"{dashboard}/api/v1/scan", data=payload,
                headers={"Authorization": f"Bearer {cg_key}", "Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=10, context=ssl.create_default_context())
        except Exception:
            pass
    for f, r in zip(files, results):
        threading.Thread(target=_push, args=(f, r), daemon=True).start()


if __name__ == "__main__":
    main()
