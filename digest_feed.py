# digest_feed.py — Heira Daily Summary → Slack
# Pulls feeds, enriches with KEV/EPSS, picks "top 5", posts one consolidated brief.

import os, re, hashlib
import feedparser, requests
from urllib.parse import urlparse
from datetime import datetime

# ----- Config -----
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
TOTAL_IN_DIGEST = 5
SLACK_WEBHOOK_DAILY = os.getenv("SLACK_WEBHOOK_DAILY") or os.getenv("SLACK_WEBHOOK_URL")

CISA_KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_API = "https://api.first.org/data/v1/epss?cve={cves}"

CVE_RE     = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

def fetch_all():
    items=[]
    for url in FEEDS:
        d = feedparser.parse(url)
        host = urlparse(url).netloc.replace("www.","")
        for e in d.entries[:15]:
            title  = (e.get("title") or "").strip()
            link   = e.get("link") or ""
            summ   = (e.get("summary") or e.get("description") or "").strip()
            if title and link:
                items.append({"title":title,"link":link,"summary":summ,"source":host})
    return items

def tags_for(text: str):
    t = (text or "").lower()
    labs = []
    if CVE_RE.search(t): labs.append("CVE")
    if any(x in t for x in ["ransomware","lockbit","blackcat","alphv","play","royal"]): labs.append("ransomware")
    if any(x in t for x in ["aws","azure","gcp","k8s","kubernetes","s3","iam","bucket","cloudtrail"]): labs.append("cloud")
    if any(x in t for x in ["okta","entra","sso","saml","oauth","mfa","passwordless"]): labs.append("identity")
    if not labs: labs.append("general")
    return labs

def get_kev_set():
    try:
        r = requests.get(CISA_KEV_URL, timeout=15)
        vulns = r.json().get("vulnerabilities", [])
        return {v.get("cveID") for v in vulns if v.get("cveID")}
    except Exception:
        return set()

def get_epss_scores(cves):
    scores={}
    if not cves: return scores
    batch = 150
    for i in range(0, len(cves), batch):
        chunk=",".join(cves[i:i+batch])
        try:
            r = requests.get(FIRST_EPSS_API.format(cves=chunk), timeout=15)
            for row in r.json().get("data", []):
                c=row.get("cve"); s=row.get("epss")
                if c and s:
                    try: scores[c.upper()] = round(float(s),3)
                    except: pass
        except: pass
    return scores

def best_epss_for(text, epss_map):
    cs = [c.upper() for c in CVE_RE.findall(text or "")]
    if not cs: return None, None
    top, top_s = None, -1.0
    for c in cs:
        s = epss_map.get(c)
        if s is not None and s > top_s:
            top, top_s = c, s
    return top, top_s if top else (None, None)

def score_item(it, kev_set, epss_map):
    txt = f"{it['title']} {it['summary']}"
    base = 1.0
    # KEV & EPSS lift
    kev = [c for c in CVE_RE.findall(txt) if c.upper() in kev_set]
    if kev: base += 2.0
    _, epss = best_epss_for(txt, epss_map)
    if epss: base += min(2.0, epss * 2.0)  # up to +2
    # Topical lift (vuln/identity/ransomware/cloud)
    tgs = tags_for(txt)
    if "CVE" in tgs: base += 0.8
    if "identity" in tgs: base += 0.4
    if "ransomware" in tgs: base += 0.3
    if "cloud" in tgs: base += 0.2
    return base

def build_digest_blocks(picks, kev_set, epss_map):
    today = datetime.utcnow().strftime("%Y-%m-%d")
    header = [
        {"type":"header","text":{"type":"plain_text","text":f"Heira — Daily Threat Brief ({today})"}},
        {"type":"context","elements":[{"type":"mrkdwn","text":"KEV/EPSS prioritized. Verify before action."}]},
        {"type":"divider"}
    ]
    blocks = header[:]
    for i, it in enumerate(picks, 1):
        full = f"{it['title']} {it['summary']}"
        tgs  = tags_for(full)
        kev  = [c for c in CVE_RE.findall(full) if c.upper() in kev_set][:3]
        top_cve, top_epss = best_epss_for(full, epss_map)
        meta=[]
        if kev: meta.append(f"*:rotating_light: KEV:* {', '.join(kev)}")
        if top_cve and top_epss is not None: meta.append(f"*EPSS:* {top_cve} → {top_epss:.3f}")
        meta.append(f"*Source:* {it['source']}")
        meta_line=" • ".join(meta)
        blocks += [
            {"type":"section","text":{"type":"mrkdwn","text":f"*{i}) {it['title']}*"}},
            {"type":"context","elements":[{"type":"mrkdwn","text": meta_line}]},
            {"type":"section","text":{"type":"mrkdwn","text": f"<{it['link']}|Read full story> • *Tags:* " + " • ".join(tgs)}},
            {"type":"divider"},
        ]
    return blocks

def slack_post(webhook, blocks):
    if not webhook:
        print("Missing SLACK_WEBHOOK_DAILY or SLACK_WEBHOOK_URL")
        return False
    r = requests.post(webhook, json={"blocks": blocks})
    if r.status_code >= 300:
        print("Slack error:", r.text)
        return False
    return True

def main():
    items = fetch_all()
    if not items:
        print("No items fetched.")
        return
    kev = get_kev_set()
    all_cves = sorted({c.upper() for it in items for c in CVE_RE.findall(it["title"]+" "+it["summary"])})
    epss = get_epss_scores(all_cves)

    # Score & pick top N with simple per-source variety
    scored = sorted(items, key=lambda x: score_item(x, kev, epss), reverse=True)
    picked, per_src = [], {}
    for it in scored:
        if per_src.get(it["source"], 0) >= 2:  # avoid one source dominating
            continue
        picked.append(it)
        per_src[it["source"]] = per_src.get(it["source"], 0) + 1
        if len(picked) >= TOTAL_IN_DIGEST:
            break

    blocks = build_digest_blocks(picked, kev, epss)
    slack_post(SLACK_WEBHOOK_DAILY, blocks)

if __name__ == "__main__":
    main()
