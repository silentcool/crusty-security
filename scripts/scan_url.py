#!/usr/bin/env python3
"""scan_url.py — Check URLs against VirusTotal and Google Safe Browsing APIs.

Usage: scan_url.py [OPTIONS] <url> [url2 ...]

Options:
  --json          JSON output (default)
  --vt-only       Only check VirusTotal
  --gsb-only      Only check Google Safe Browsing
  -h, --help      Show help

Environment:
  VIRUSTOTAL_API_KEY         VirusTotal API key
  GOOGLE_SAFE_BROWSING_KEY   Google Safe Browsing API key
"""

import json
import os
import sys
import hashlib
import time
from datetime import datetime, timezone

try:
    import urllib.request
    import urllib.parse
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


def show_help():
    print(__doc__)
    sys.exit(0)


def http_get(url, headers=None, timeout=15):
    """HTTP GET with requests or urllib fallback."""
    if HAS_REQUESTS:
        r = requests.get(url, headers=headers or {}, timeout=timeout)
        return r.status_code, r.text
    elif HAS_URLLIB:
        req = urllib.request.Request(url, headers=headers or {})
        ctx = ssl.create_default_context()
        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")
    else:
        raise RuntimeError("No HTTP library available (need requests or urllib)")


def http_post(url, data, headers=None, timeout=15):
    """HTTP POST with requests or urllib fallback."""
    if HAS_REQUESTS:
        r = requests.post(url, json=data, headers=headers or {}, timeout=timeout)
        return r.status_code, r.text
    elif HAS_URLLIB:
        payload = json.dumps(data).encode("utf-8")
        hdrs = {"Content-Type": "application/json"}
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")
        ctx = ssl.create_default_context()
        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")
    else:
        raise RuntimeError("No HTTP library available")


def resolve_url(url):
    """Resolve redirects to get final URL."""
    try:
        if HAS_REQUESTS:
            r = requests.head(url, allow_redirects=True, timeout=10)
            return r.url
        elif HAS_URLLIB:
            req = urllib.request.Request(url, method="HEAD")
            ctx = ssl.create_default_context()
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            return resp.url
    except Exception:
        pass
    return url


def check_virustotal(url, api_key):
    """Check URL against VirusTotal."""
    url_id = hashlib.sha256(url.encode()).hexdigest()
    # First try to get existing report by URL ID
    # VT uses base64url of the URL as identifier
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}

    status_code, body = http_get(endpoint, headers=headers)

    if status_code == 404:
        # URL not in VT database, submit it
        if HAS_REQUESTS:
            r = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15,
            )
            if r.status_code == 200:
                # Get the analysis
                analysis = r.json().get("data", {}).get("id", "")
                time.sleep(3)  # Wait for analysis
                status_code, body = http_get(endpoint, headers=headers)
            else:
                return {"source": "virustotal", "status": "error", "message": f"Submit failed: {r.status_code}"}
        else:
            return {"source": "virustotal", "status": "not_found", "message": "URL not in VT database"}

    if status_code == 200:
        data = json.loads(body)
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {
            "source": "virustotal",
            "status": verdict,
            "detections": {"malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected, "total": total},
            "url": url,
        }
    elif status_code == 429:
        return {"source": "virustotal", "status": "rate_limited", "message": "API rate limit exceeded. Free tier: 4 req/min."}
    else:
        return {"source": "virustotal", "status": "error", "message": f"HTTP {status_code}"}


def check_google_safe_browsing(url, api_key):
    """Check URL against Google Safe Browsing."""
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "clawguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    status_code, body = http_post(endpoint, payload)

    if status_code == 200:
        data = json.loads(body)
        matches = data.get("matches", [])
        if matches:
            threats = [m.get("threatType", "UNKNOWN") for m in matches]
            return {"source": "google_safe_browsing", "status": "malicious", "threats": threats, "url": url}
        else:
            return {"source": "google_safe_browsing", "status": "clean", "url": url}
    else:
        return {"source": "google_safe_browsing", "status": "error", "message": f"HTTP {status_code}"}


def scan_url(url, vt_only=False, gsb_only=False):
    """Scan a single URL."""
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    gsb_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")

    # Resolve redirects
    resolved = resolve_url(url)

    result = {
        "url": url,
        "resolved_url": resolved if resolved != url else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": [],
        "overall_status": "unknown",
    }

    warnings = []

    if not gsb_only and vt_key:
        result["checks"].append(check_virustotal(resolved, vt_key))
    elif not gsb_only:
        warnings.append("VIRUSTOTAL_API_KEY not set — skipping VirusTotal check")

    if not vt_only and gsb_key:
        result["checks"].append(check_google_safe_browsing(resolved, gsb_key))
    elif not vt_only:
        warnings.append("GOOGLE_SAFE_BROWSING_KEY not set — skipping Google Safe Browsing check")

    if warnings:
        result["warnings"] = warnings

    # Determine overall status
    statuses = [c.get("status") for c in result["checks"]]
    if "malicious" in statuses:
        result["overall_status"] = "malicious"
    elif "suspicious" in statuses:
        result["overall_status"] = "suspicious"
    elif "clean" in statuses:
        result["overall_status"] = "clean"
    elif not result["checks"]:
        result["overall_status"] = "no_checks_available"

    return result


def main():
    args = sys.argv[1:]
    vt_only = False
    gsb_only = False
    urls = []

    for arg in args:
        if arg in ("-h", "--help"):
            show_help()
        elif arg == "--vt-only":
            vt_only = True
        elif arg == "--gsb-only":
            gsb_only = True
        elif arg == "--json":
            pass
        elif arg.startswith("http://") or arg.startswith("https://"):
            urls.append(arg)
        else:
            urls.append(arg)  # Accept non-prefixed URLs too

    if not urls:
        print(json.dumps({"status": "error", "message": "No URLs provided. Use --help for usage."}))
        sys.exit(2)

    results = []
    for url in urls:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        results.append(scan_url(url, vt_only=vt_only, gsb_only=gsb_only))

    if len(results) == 1:
        print(json.dumps(results[0], indent=2))
    else:
        print(json.dumps({"results": results}, indent=2))

    # Push to dashboard
    _push_url_scans(urls, results)

    # Exit code based on worst result
    all_statuses = [r["overall_status"] for r in results]
    if "malicious" in all_statuses:
        sys.exit(1)
    elif "suspicious" in all_statuses:
        sys.exit(1)
    sys.exit(0)


def _push_url_scans(urls, results):
    """Push URL scan results to ClawGuard dashboard."""
    api_key = os.environ.get("CLAWGUARD_API_KEY", "")
    dashboard_url = os.environ.get("CLAWGUARD_DASHBOARD_URL", "https://clawguard-rust.vercel.app")
    if not api_key:
        return
    
    import threading
    def _push(url, result):
        try:
            severity_map = {"clean": "none", "suspicious": "high", "malicious": "critical", "error": "none"}
            payload = json.dumps({
                "scan_type": "url",
                "target": url,
                "status": result.get("overall_status", "clean"),
                "engine": "VirusTotal + Safe Browsing",
                "severity": severity_map.get(result.get("overall_status", "clean"), "none"),
                "duration_ms": 0,
                "results": result
            }).encode()
            req = urllib.request.Request(
                f"{dashboard_url}/api/v1/scan",
                data=payload,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                method="POST"
            )
            ctx = ssl.create_default_context()
            urllib.request.urlopen(req, timeout=10, context=ctx)
        except Exception:
            pass
    
    for url, result in zip(urls, results):
        t = threading.Thread(target=_push, args=(url, result), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
