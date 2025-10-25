# intel_feed.py — Heira Threat Intel → Slack (+ optional SMS)
# Adds: TL;DR, What it is, Recommended actions; KEV/EPSS, IOCs, per-tag routing.

import os, re, hashlib
import feedparser, requests
from urllib.parse import urlparse

# ================= CONFIG =================
FEEDS = [
    "https://www.cisa.gov/news.xml",
    "https://cyware.com/all-news/feed",
    "https://thecyberwire.com/feeds/rss/daily-briefing",
    "https://www.bleepingcomputer.com/feed/",
    "https://therecord.media/feed",
    "https://www.darkreading.com/rss.xml",
    "https://www.securityweek.com/feed",
    "https://blog.talosintelligence.com/rss/",
    "https://krebsonsecurity.com/feed/",
]

MAX_PER_RUN      = 6          # total per run
MAX_PER_SOURCE   = 3          # variety cap
ONLY_IF_MATCH    = []         # [] → send everything; or add keywords to filter
STATE_FILE       = ".sent_hashes"

# Default + per-tag Slack webhooks (optional)
SLACK_WEBHOOK_URL        = os.getenv("SLACK_WEBHOOK_URL")
SLACK_WEBHOOK_VULN       = os.getenv("SLACK_WEBHOOK_VULN")        # CVE items
SLACK_WEBHOOK_RANSOMWARE = os.getenv("SLACK_WEBHOOK_RANSOMWARE")  # ransomware
SLACK_WEBHOOK_CLOUD      = os.getenv("SLACK_WEBHOOK_CLOUD")       # cloud/IaaS
SLACK_WEBHOOK_IDENTITY   = os.getenv("SLACK_WEBHOOK_IDENTITY")    # auth/SSO/IdP

# Optional Twilio SMS
TWILIO_SID  = os.getenv("TWILIO_SID", "")
TWILIO_AUTH = os.getenv("TWILIO_AUTH", "")
TWILIO_FROM = os.getenv("TWILIO_FROM", "")
TWILIO_TO   = os.getenv("TWILIO_TO", "")

# Enrichment
CISA_KEV_URL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_API   = "https://api.first.org/data/v1/epss?cve={cves}"

# ================= Helpers =================
CVE_RE     = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
DOMAIN_RE  = re.compile(r"\b(?:(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,}))\b", re.I)
IPV4_RE    = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}\b")
SHA256_RE  = re.compile(r"\b[a-f0-9]{64}\b", re.I)
SHA1_RE    = re.compile(r"\b[a-f0-9]{40}\b", re.I)
MD5_RE     = re.compile(r"\b[a-f0-9]{32}\b", re.I)

MITIGATION_MAP = {
    "CVE": [
        "Patch/update per vendor guidance; prioritize if in CISA KEV.",
        "Mitigate exposed services (WAF/IPS/geo) until patched.",
        "Hunt for exploit IoCs; scan perimeter for exposure."
    ],
    "ransomware": [
        "Enforce phishing-resistant MFA; disable legacy auth.",
        "Keep offline, immutable backups and test restores.",
        "Block macros/LOLbins; enable EDR + script logging."
    ],
    "cloud": [
        "Tighten IAM least privilege; review high-risk roles/keys.",
        "Enable CSPM policies + threat alerts; guardrails for public buckets.",
        "Ensure audit logs on (CloudTrail/Activity) and alerts wired."
    ],
    "identity": [
        "Conditional Access / risk-based auth; block legacy protocols.",
        "Monitor OAuth/app consent; review recent high-risk sign-ins.",
        "Rotate/disable compromised creds; enforce MFA everywhere."
    ],
    "general": [
        "Verify source details; share to right owners (IT/Cloud/AppSec).",
        "Log + telemetry checks for related TTPs; update detections.",
        "User heads-up if relevant (fraud/phishing themes)."
    ]
}

WHAT_IS_MAP = {
    "CVE": "A specific vulnerability identifier (CVE) that vendors patch and attackers may exploit.",
    "ransomware": "Malware that encrypts data and demands payment; often enters via phishing or exposed services.",
    "cloud": "Configuration or service abuse in AWS/Azure/GCP (e.g., IAM, buckets, k8s).",
    "identity": "Attacks against SSO/MFA/session tokens or IdP misconfigurations.",
    "general": "Security news that may affect policy, detection, or awareness."
}

def h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def short(text: str, n=260) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return (text[: n - 1] + "…") if len(text) > n else text

def extract_iocs(text: str):
    text = text or ""
    harmless = {
        "cisa.gov","bleepingcomputer.com","therecord.media","darkreading.com",
        "securityweek.com","cyware.com","thecyberwire.com","krebsonsecurity.com",
        "blog.talosintelligence.com"
    }
    doms = {d for d in DOMAIN_RE.findall(text) if d.lower() not in harmless}
    ips  = set(IPV4_RE.findall(text))
    hashes = set(SHA256_RE.findall(text)) or set(SHA1_RE.findall(text)) or set(MD5_RE.findall(text))
    return {"domains": sorted(doms)[:5], "ips": sorted(ips)[:5], "hashes": sorted(hashes)[:5]}

def tags_for(text: str):
    t = (text or "").lower()
    labs = []
    if CVE_RE.search(t): labs.append("CVE")
    if any(x in t for x in ["ransomware","lockbit","blackcat","alphv"]): labs.append("ransomware")
    if any(x in t for x in ["aws","azure","gcp","k8s","kubernetes","s3","iam","bucket"]): labs.append("cloud")
    if any(x in t for x in ["okta","entra","sso","saml","oauth","mfa"]): labs.append("identity")
    if not labs: labs.append("general")
    return labs

def allowed(title: str, summary: str):
    if not ONLY_IF_MATCH: return True
    t = f"{title} {summary}".lower()
    return any(k.lower() in t for k in ONLY_IF_MATCH)

def load_sent():
    s=set()
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE,"r",encoding="utf-8") as f:
            for line in f: s.add(line.strip())
    return s

def save_sent(s:set):
    with open(STATE_FILE,"w",encoding="utf-8") as f:
        for x in sorted(s): f.write(x+"\n")

def fetch_all():
    items=[]
    for url in FEEDS:
        d = feedparser.parse(url)
        host = urlparse(url).netloc.replace("www.","")
        for e in d.entries[:15]:
            title  = (e.get("title") or "").strip()
            link   = e.get("link") or ""
            summary= (e.get("summary") or e.get("description") or "").strip()
            if title and link:
                items.append({"title":title,"link":link,"summary":summary,"source":host})
    return items

def pick(items, sent_hashes):
    per_src, picked, seen = {}, [], set()
    for it in items:
        key = h(f"{it['source']}|{it['title'].lower()}")
        if key in seen or key in sent_hashes: continue
        if not allowed(it["title"], it["summary"]): continue
        if per_src.get(it["source"],0) >= MAX_PER_SOURCE: continue
        it["hash"]=key
        seen.add(key); per_src[it["source"]]=per_src.get(it["source"],0)+1
        picked.append(it)
        if len(picked)>=MAX_PER_RUN: break
    return picked

# ---------- Enrichment ----------
def unwrap_url(url: str) -> str:
    try:
        r = requests.head(url, allow_redirects=True, timeout=8)
        if 200 <= r.status_code < 400: return r.url
    except Exception: pass
    try:
        r = requests.get(url, allow_redirects=True, timeout=8)
        if 200 <= r.status_code < 400: return r.url
    except Exception: pass
    return url

def get_kev_set():
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=15)
        vulns = r.json().get("vulnerabilities", [])
        return {v.get("cveID") for v in vulns if v.get("cveID")}
    except Exception:
        return set()

def get_epss_scores(cves):
    scores={}
    if not cves: return scores
    batch_size = 150
    for i in range(0, len(cves), batch_size):
        chunk = ",".join(cves[i:i+batch_size])
        try:
            r = requests.get(f"https://api.first.org/data/v1/epss?cve={chunk}", timeout=15)
            for row in r.json().get("data", []):
                cve=row.get("cve"); s=row.get("epss")
                if cve and s: 
                    try: scores[cve.upper()] = round(float(s),3)
                    except Exception: pass
        except Exception:
            continue
    return scores

def best_epss_for(text, epss_map):
    cves = [c.upper() for c in CVE_RE.findall(text or "")]
    if not cves: return None, None
    top, top_s = None, -1.0
    for c in cves:
        s = epss_map.get(c)
        if s is not None and s > top_s:
            top, top_s = c, s
    return top, top_s if top else (None, None)

# ---------- Brief generation ----------
def tldr_from(title, summary):
    s = re.sub(r"\s+"," ", summary or "").strip()
    if not s: return title
    parts = re.split(r"(?<=[.!?])\s+", s)
    out = " ".join(parts[:2])[:240]
    return out if out else title

def what_is_for(tags):
    for t in ["CVE","ransomware","cloud","identity"]:
        if t in tags: return WHAT_IS_MAP[t]
    return WHAT_IS_MAP["general"]

def mitigations_for(tags):
    seen=set(); out=[]
    for t in tags:
        for m in MITIGATION_MAP.get(t, []):
            if m not in seen:
                out.append("• "+m); seen.add(m)
    if not out:
        for m in MITIGATION_MAP["general"]:
            out.append("• "+m)
    return out[:5]

# ---------- Slack ----------
def choose_webhook(tags):
    if "CVE" in tags and SLACK_WEBHOOK_VULN: return SLACK_WEBHOOK_VULN
    if "ransomware" in tags and SLACK_WEBHOOK_RANSOMWARE: return SLACK_WEBHOOK_RANSOMWARE
    if "cloud" in tags and SLACK_WEBHOOK_CLOUD: return SLACK_WEBHOOK_CLOUD
    if "identity" in tags and SLACK_WEBHOOK_IDENTITY: return SLACK_WEBHOOK_IDENTITY
    return SLACK_WEBHOOK_URL

def slack_post(webhook, blocks):
    if not webhook:
        print("Missing Slack webhook env.")
        return False
    r = requests.post(webhook, json={"blocks": blocks})
    if r.status_code >= 300:
        print("Slack error:", r.text)
        return False
    return True

def build_blocks(items, kev_set, epss_map):
    head = [
        {"type":"header","text":{"type":"plain_text","text":"Heira — Threat Intel Updates"}},
        {"type":"context","elements":[{"type":"mrkdwn","text":"Auto-curated with KEV/EPSS. Verify before action."}]},
        {"type":"divider"}
    ]
    routed=[]
    for it in items:
        full = f"{it['title']} {it['summary']}"
        tgs  = tags_for(full)
        iocs = extract_iocs(full)
        cves = [c.upper() for c in CVE_RE.findall(full)]
        kev  = [c for c in cves if c in kev_set][:3]
        top_cve, top_epss = best_epss_for(full, epss_map)

        tl   = tldr_from(it["title"], it["summary"])
        what = what_is_for(tgs)
        acts = mitigations_for(tgs)
        link = unwrap_url(it["link"])

        meta_bits=[]
        if kev: meta_bits.append(f"*:rotating_light: KEV:* {', '.join(kev)}")
        if top_cve and top_epss is not None: meta_bits.append(f"*EPSS:* {top_cve} → {top_epss:.3f}")
        meta_bits.append(f"*Source:* {it['source']}")
        meta_line=" • ".join(meta_bits)

        ioc_lines=[]
        if iocs["domains"]: ioc_lines.append("Domains: " + ", ".join(iocs["domains"]))
        if iocs["ips"]:     ioc_lines.append("IPs: " + ", ".join(iocs["ips"]))
        if iocs["hashes"]:  ioc_lines.append("Hashes: " + ", ".join(iocs["hashes"]))
        ioc_text = "\n".join(ioc_lines)

        blocks = head + [
            {"type":"section","text":{"type":"mrkdwn","text":f"*{it['title']}*"}},
            {"type":"context","elements":[{"type":"mrkdwn","text": meta_line}]},
            {"type":"section","text":{"type":"mrkdwn","text":f"*What’s happening (TL;DR):*\n{short(tl, 420)}"}},
            {"type":"section","text":{"type":"mrkdwn","text":f"*What it is:*\n{what}"}},
            {"type":"section","text":{"type":"mrkdwn","text":"*How to defend:*\n" + "\n".join(acts)}},
            {"type":"section","text":{"type":"mrkdwn","text":f"<{link}|Read full story> • *Tags:* " + " • ".join(tgs)}},
        ]
        if ioc_text:
            blocks.append({"type":"section","text":{"type":"mrkdwn","text":"*IOCs*\n"+ioc_text}})
        blocks.append({"type":"divider"})

        routed.append((choose_webhook(tgs), blocks))
    return routed

# ---------- SMS ----------
def sms_send(body):
    if not all([TWILIO_SID,TWILIO_AUTH,TWILIO_FROM,TWILIO_TO]): return
    from requests.auth import HTTPBasicAuth
    url = f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_SID}/Messages.json"
    data = {"From":TWILIO_FROM,"To":TWILIO_TO,"Body":body[:1400]}
    r = requests.post(url,data=data,auth=HTTPBasicAuth(TWILIO_SID,TWILIO_AUTH))
    if r.status_code >= 300: print("Twilio error:", r.text)

# ================= Main =================
def main():
    sent = load_sent()
    items = fetch_all()
    picked = pick(items, sent)
    if not picked:
        print("No new items.")
        return

    kev = get_kev_set()
    all_cves = sorted({c.upper() for it in picked for c in CVE_RE.findall(it["title"]+" "+it["summary"])})
    epss = get_epss_scores(all_cves)

    for webhook, blocks in build_blocks(picked, kev, epss):
        slack_post(webhook, blocks)

    for it in picked: sent.add(it["hash"])
    save_sent(sent)

    digest = "Heira Intel:\n" + "\n".join("• " + short(it["title"], 90) for it in picked[:3])
    sms_send(digest)

if __name__ == "__main__":
    main()
