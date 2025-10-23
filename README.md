# Heira Security — Auto‑Curated Cyber Newsletter (Starter Kit)

This kit pulls from multiple cyber news feeds (including Cyware Social and The CyberWire), summarizes items,
maps them to actionable mitigations, and renders a **Heira‑branded** email + web newsletter.

## Structure
```
heira_newsletter_kit/
  assets/               # put heira-logo.png here
  config/
    brand.json          # colors, logo path, footer note
    feeds.yaml          # list of RSS feeds
  templates/
    heira_email.html    # email‑friendly Jinja template
    heira_web.html      # web page Jinja template
  output/
    newsletter_email.html
    newsletter_web.html
  heira_newsletter.py   # main script
```

## Quickstart
1) **Upload your logo** to `assets/heira-logo.png` (PNG, ~600px wide recommended).
2) (Optional) Update `config/brand.json` colors and footer text.
3) (Optional) Adjust feeds in `config/feeds.yaml` (verify the Cyware & CyberWire RSS paths you prefer).
4) Install deps:
```
pip install feedparser jinja2 pyyaml transformers torch
```
5) Run:
```
python heira_newsletter.py
```
6) Open the rendered files in `output/`:
- `newsletter_email.html` → paste into Mailchimp/SendGrid custom HTML
- `newsletter_web.html` → publish to your site or Substack/beehiiv custom page

## Notes
- Summarization uses a lightweight local model if available; otherwise a simple extractive fallback is used.
- Respect each source’s Terms of Use; the newsletter links to the original stories and uses original summaries.
- You can expand the **MITIGATION_MAP** for deeper guidance (CIS, NIST CSF, ATT&CK).
- Consider adding CISA KEV + EPSS scoring later for smarter prioritization.