import os, re, json, yaml, datetime, hashlib
import feedparser
from urllib.parse import urlparse
from jinja2 import Environment, FileSystemLoader

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- Load config ---
with open(os.path.join(CONFIG_DIR, "brand.json"), "r", encoding="utf-8") as f:
    brand = json.load(f)

with open(os.path.join(CONFIG_DIR, "feeds.yaml"), "r", encoding="utf-8") as f:
    feeds_cfg = yaml.safe_load(f)
FEEDS = feeds_cfg.get("feeds", [])

# --- Topic → mitigations mapping (expand as needed) ---
MITIGATION_MAP = {
    "ransomware": [
        "Test restores from offline, immutable backups (NIST CSF: Recover).",
        "Enforce phishing-resistant MFA for remote access (CIS 6; ATT&CK M1032).",
        "Block macros; enable script/AMSI logging; alert on suspicious LOLBins."
    ],
    "phishing": [
        "Add external sender banner and display name checks (CIS 9).",
        "Enforce MFA; disable legacy auth; enable token protections.",
        "Microtraining + report-phish button to reinforce reporting."
    ],
    "cve": [
        "Prioritize patch if in CISA KEV; apply vendor guidance.",
        "Use WAF/IPS virtual patching if patching is delayed.",
        "Hunt for exploit IoCs; scan perimeter and EASM for exposure."
    ],
    "identity": [
        "Conditional Access: block legacy; enforce step-up MFA.",
        "Rotate high-risk creds; monitor OAuth consent grants.",
        "Alert on impossible travel and atypical session patterns."
    ],
    "cloud": [
        "Enable CSPM policies and least privilege IAM.",
        "Ensure logging (CloudTrail/Azure Activity) & threat alerts.",
        "Block public buckets by policy; rotate keys; scan IaC for drift."
    ],
}

# --- Optional: transformer summarizer (fallback to extractive) ---
SUMMARIZER = None
try:
    from transformers import pipeline
    SUMMARIZER = pipeline("summarization", model="sshleifer/distilbart-cnn-12-6")
except Exception:
    pass

def summarize(text: str) -> str:
    text = re.sub(r"\s+", " ", (text or "")).strip()
    if not text:
        return ""
    if SUMMARIZER:
        try:
            return SUMMARIZER(text[:3000], max_length=110, min_length=60, do_sample=False)[0]["summary_text"]
        except Exception:
            pass
    # Extractive fallback: first 2-3 sentences
    sents = re.split(r"(?<=[.!?])\s+", text)
    return " ".join(sents[:3])[:800]

def guess_topics(title: str, summary: str):
    t = f"{title} {summary}".lower()
    topics = set()
    if any(k in t for k in ["ransomware", "lockbit", "blackcat", "play", "royal"]): topics.add("ransomware")
    if any(k in t for k in ["phish", "spoof", "smishing", "vishing", "credential", "invoice scam"]): topics.add("phishing")
    if re.search(r"\bCVE-\d{4}-\d+\b", t): topics.add("cve")
    if any(k in t for k in ["entra", "azure ad", "okta", "sso", "saml", "oauth", "mfa"]): topics.add("identity")
    if any(k in t for k in ["aws", "azure", "gcp", "s3", "bucket", "kubernetes", "k8s", "iam"]): topics.add("cloud")
    return topics or {"phishing"}

def hash_key(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def fetch_items():
    items = []
    for url in FEEDS:
        try:
            d = feedparser.parse(url)
            for e in d.entries[:20]:
                title = e.get("title", "").strip()
                link  = e.get("link", "")
                summary = (e.get("summary", "") or e.get("description","") or "").strip()
                published = e.get("published", "") or e.get("updated","")
                source = urlparse(url).netloc.replace("www.","")
                if title and link:
                    items.append({
                        "title": title, "link": link, "summary": summary,
                        "published": published, "source": source
                    })
        except Exception as ex:
            # continue on single feed errors
            pass
    return items

def dedupe(items):
    seen = set(); out = []
    for it in items:
        k = hash_key(f"{it['source']}|{it['title'].lower()}")
        if k in seen: 
            continue
        seen.add(k); out.append(it)
    return out

SOURCE_WEIGHT = {
    "cisa.gov": 3.0, "nvd.nist.gov": 2.5, "therecord.media": 2.0,
    "bleepingcomputer.com": 1.8, "darkreading.com": 1.6, "securityweek.com": 1.4,
    "cyware.com": 1.6, "thecyberwire.com": 1.8
}

def score(item):
    s = 1.0 + (SOURCE_WEIGHT.get(item["source"], 1.0) - 1.0)
    if re.search(r"\bCVE-\d{4}-\d+\b", f"{item['title']} {item['summary']}"): s += 0.8
    if any(x in item["title"].lower() for x in ["0-day","zero-day","actively exploited","kev"]): s += 0.6
    s += 0.2
    return s

def render(articles, brand, edition_label="Heira Threat Brief", web_url="#"):
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    ctx = {
        "brand": brand,
        "edition_label": edition_label,
        "title": f"{edition_label} — {datetime.date.today().isoformat()}",
        "published": datetime.datetime.now().strftime("%B %d, %Y %I:%M %p %Z"),
        "articles": articles,
        "year": datetime.date.today().year,
        "web_edition_url": web_url,
    }
    # email
    tmpl_email = env.get_template("heira_email.html")
    email_html = tmpl_email.render(**ctx)
    with open(os.path.join(OUTPUT_DIR, "newsletter_email.html"), "w", encoding="utf-8") as f:
        f.write(email_html)
    # web
    tmpl_web = env.get_template("heira_web.html")
    web_html = tmpl_web.render(**ctx)
    with open(os.path.join(OUTPUT_DIR, "newsletter_web.html"), "w", encoding="utf-8") as f:
        f.write(web_html)
    return email_html, web_html

def main():
    raw = fetch_items()
    raw = dedupe(raw)
    raw = sorted(raw, key=score, reverse=True)[:10]

    articles = []
    for it in raw:
        tldr = summarize(it.get("summary") or it.get("title"))
        why = "Potential impact to confidentiality, integrity, or availability. Prioritize if you run affected tech or observe related TTPs."
        tags = sorted(list(guess_topics(it["title"], tldr)))
        mitigations = []
        for t in tags:
            mitigations.extend(MITIGATION_MAP.get(t, []))
        # unique
        uniq = []
        seen = set()
        for m in mitigations:
            if m not in seen:
                seen.add(m); uniq.append(m)
        articles.append({
            "title": it["title"],
            "source": it["source"],
            "link": it["link"],
            "tldr": tldr,
            "why": why,
            "tags": tags,
            "mitigations": uniq[:6]
        })

    render(articles, brand, edition_label="Heira Threat Brief", web_url="#")
    print("Wrote: output/newsletter_email.html and output/newsletter_web.html")

if __name__ == "__main__":
    main()